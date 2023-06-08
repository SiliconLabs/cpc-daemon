/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - System Endpoint
 *******************************************************************************
 * # License
 * <b>Copyright 2022 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "cpcd/config.h"
#include "cpcd/logging.h"
#include "cpcd/server_core.h"
#include "cpcd/utils.h"

#include "server_core/core/hdlc.h"
#include "sl_cpc.h"
#include "system.h"

#include "server_core/system_endpoint/system_callbacks.h"
#include "server_core/server/server.h"
#include "server_core/core/core.h"
#include "security/security.h"

/***************************************************************************//**
 * How long to wait before attempting another command that requires an unnumbered ack
 ******************************************************************************/
#define UNNUMBERED_ACK_TIMEOUT_SECONDS 2

/***************************************************************************//**
 * Used to return the size of a system command buffer, primarily to pass to
 * sl_cpc_write.
 ******************************************************************************/
#define SIZEOF_SYSTEM_COMMAND(command) (sizeof(sl_cpc_system_cmd_t) + command->length)

/***************************************************************************//**
 * Number of retries for set property endpoint closed.
 ******************************************************************************/
#define ENDPOINT_CLOSE_RETRIES 5

/***************************************************************************//**
 * Timeout in usec for set property endpoint closed.
 ******************************************************************************/
#define ENDPOINT_CLOSE_RETRY_TIMEOUT 100000

static sl_slist_node_t *pending_commands;
static sl_slist_node_t *commands;
static sl_slist_node_t *retries;
static sl_slist_node_t *commands_in_error;

static bool received_remote_sequence_numbers_reset_ack = true;

extern bool ignore_reset_reason;

typedef struct {
  sl_slist_node_t node;
  sl_cpc_system_unsolicited_status_callback_t callback;
}prop_last_status_callback_list_item_t;

static sl_slist_node_t *prop_last_status_callbacks;

static void on_iframe_unsolicited(uint8_t endpoint_id, const void* data, size_t data_len);
static void on_uframe_receive(uint8_t endpoint_id, const void* data, size_t data_len);
static void on_reply(uint8_t endpoint_id, void *arg, void *answer, uint32_t answer_lenght);
static void on_timer_expired(epoll_private_data_t *private_data);
static void write_command(sl_cpc_system_command_handle_t *command_handle);

static void sl_cpc_system_cmd_abort(sl_cpc_system_command_handle_t *command_handle, sl_status_t error);

static void sl_cpc_system_open_endpoint(void)
{
  core_open_endpoint(SL_CPC_ENDPOINT_SYSTEM, SL_CPC_OPEN_ENDPOINT_FLAG_UFRAME_ENABLE, 1, false);

  core_set_endpoint_option(SL_CPC_ENDPOINT_SYSTEM,
                           SL_CPC_ENDPOINT_ON_FINAL,
                           on_reply);

  core_set_endpoint_option(SL_CPC_ENDPOINT_SYSTEM,
                           SL_CPC_ENDPOINT_ON_UFRAME_RECEIVE,
                           on_uframe_receive);

  core_set_endpoint_option(SL_CPC_ENDPOINT_SYSTEM,
                           SL_CPC_ENDPOINT_ON_IFRAME_RECEIVE,
                           on_iframe_unsolicited);
}

static void sl_cpc_system_init_command_handle(sl_cpc_system_command_handle_t *command_handle,
                                              void *on_final,
                                              uint8_t retry_count,
                                              uint32_t retry_timeout_us,
                                              bool is_uframe)
{
  static uint8_t next_command_seq = 0;

  BUG_ON(command_handle == NULL);
  BUG_ON(on_final == NULL);
  command_handle->acked = false;
  command_handle->error_status = SL_STATUS_OK;

  command_handle->on_final = on_final;
  command_handle->retry_count = retry_count;
  command_handle->retry_timeout_us = retry_timeout_us;
  command_handle->command_seq = next_command_seq++;
  command_handle->is_uframe = is_uframe;
}

const char* sl_cpc_system_bootloader_type_to_str(sl_cpc_bootloader_t bootloader)
{
  switch (bootloader) {
    case SL_CPC_BOOTLOADER_NONE:
      return "None";
    case SL_CPC_BOOTLOADER_EMBER_APPLICATION:
      return "Ember Application";
    case SL_CPC_BOOTLOADER_EMBER_STANDALONE:
      return "Ember Standalone";
    case SL_CPC_BOOTLOADER_GECKO:
      return "Gecko SDK";
    case SL_CPC_BOOTLOADER_UNKNOWN:
      return "Unknown";
    default:
      return "Unexpected Value";
  }
}

void sl_cpc_system_init(void)
{
  sl_slist_init(&commands);
  sl_slist_init(&retries);
  sl_slist_init(&pending_commands);
  sl_slist_init(&commands_in_error);
  sl_slist_init(&prop_last_status_callbacks);

  sl_cpc_system_open_endpoint();
}

void sl_cpc_system_register_unsolicited_prop_last_status_callback(sl_cpc_system_unsolicited_status_callback_t callback)
{
  prop_last_status_callback_list_item_t* item = zalloc(sizeof(prop_last_status_callback_list_item_t));
  FATAL_ON(item == NULL);

  item->callback = callback;

  sl_slist_push_back(&prop_last_status_callbacks, &item->node);
}

/***************************************************************************//**
* Abort a pending system command by providing the error cause
*******************************************************************************/
static void sl_cpc_system_cmd_abort(sl_cpc_system_command_handle_t *command_handle, sl_status_t error)
{
  // Stop the re_transmit timer
  if (command_handle->re_transmit_timer_private_data.file_descriptor != 0) {
    if (command_handle->is_uframe || command_handle->acked == true) {
      epoll_unregister(&command_handle->re_transmit_timer_private_data);
    }
    close(command_handle->re_transmit_timer_private_data.file_descriptor);
    command_handle->re_transmit_timer_private_data.file_descriptor = 0;
  }

  command_handle->error_status = error; //This will be propagated when calling the callbacks

  switch (command_handle->command->command_id) {
    case CMD_SYSTEM_NOOP:
      ((sl_cpc_system_noop_cmd_callback_t)command_handle->on_final)(command_handle, command_handle->error_status);
      break;

    case CMD_SYSTEM_RESET:
      ((sl_cpc_system_reset_cmd_callback_t)command_handle->on_final)(command_handle, command_handle->error_status, STATUS_FAILURE);
      break;

    case CMD_SYSTEM_PROP_VALUE_GET:
    case CMD_SYSTEM_PROP_VALUE_SET:
    {
      sl_cpc_system_property_cmd_t *tx_property_command = (sl_cpc_system_property_cmd_t *)command_handle->command->payload;

      ((sl_cpc_system_property_get_set_cmd_callback_t) command_handle->on_final)(command_handle,
                                                                                 tx_property_command->property_id,
                                                                                 NULL,
                                                                                 0,
                                                                                 command_handle->error_status);
    }
    break;

    case CMD_SYSTEM_PROP_VALUE_IS: //fall through
    default:
      BUG("Invalid command_id");
      break;
  }

  // Invalidate the command id, now that it is aborted
  command_handle->command->command_id = CMD_SYSTEM_INVALID;
}

/***************************************************************************//**
* Handle the case where the system command timed out
*******************************************************************************/
static void sl_cpc_system_cmd_timed_out(const void *frame_data)
{
  sl_cpc_system_command_handle_t *command_handle;
  sl_cpc_system_cmd_t *timed_out_command;

  FATAL_ON(frame_data == NULL);

  timed_out_command = (sl_cpc_system_cmd_t *)frame_data;

  /* Go through the list of pending requests to find the one for which this reply applies */
  SL_SLIST_FOR_EACH_ENTRY(commands, command_handle, sl_cpc_system_command_handle_t, node_commands) {
    if (command_handle->command_seq == timed_out_command->command_seq) {
      break;
    }
  }

  if (command_handle == NULL || command_handle->command_seq != timed_out_command->command_seq) {
    BUG("A command timed out but it could not be found in the submitted commands list. SEQ#%d", timed_out_command->command_seq);
  }

  // We won't need this command anymore. It needs to be resubmitted.
  sl_slist_remove(&commands, &command_handle->node_commands);

  TRACE_SYSTEM("Command ID #%u SEQ #%u timeout", command_handle->command->command_id, command_handle->command->command_seq);

  sl_cpc_system_cmd_abort(command_handle, SL_STATUS_TIMEOUT);

  /* Free the command handle and its buffer */

  free(command_handle->command);
  free(command_handle);
}

/***************************************************************************//**
* Start the process timer once the poll command has been acknowledged
*******************************************************************************/
void sl_cpc_system_cmd_poll_acknowledged(const void *frame_data)
{
  int timer_fd, ret;
  sl_cpc_system_command_handle_t *command_handle;
  FATAL_ON(frame_data == NULL);
  sl_cpc_system_cmd_t *acked_command = (sl_cpc_system_cmd_t *)frame_data;

  // Go through the command list to figure out which command just got acknowledged
  SL_SLIST_FOR_EACH_ENTRY(commands, command_handle, sl_cpc_system_command_handle_t, node_commands) {
    if (command_handle->command_seq == acked_command->command_seq) {
      TRACE_SYSTEM("Secondary acknowledged command_id #%d command_seq #%d", command_handle->command->command_id, command_handle->command_seq);
      const struct itimerspec timeout = { .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
                                          .it_value    = { .tv_sec = (long int)command_handle->retry_timeout_us / 1000000, .tv_nsec = ((long int)command_handle->retry_timeout_us * 1000) % 1000000000 } };

      /* Setup timeout timer.*/
      if (command_handle->error_status == SL_STATUS_OK) {
        timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);

        FATAL_SYSCALL_ON(timer_fd < 0);

        ret = timerfd_settime(timer_fd, 0, &timeout, NULL);
        FATAL_SYSCALL_ON(ret < 0);

        /* Setup the timer in the server_core epoll set */
        command_handle->re_transmit_timer_private_data.endpoint_number = SL_CPC_ENDPOINT_SYSTEM; //Irrelevant in this scenario
        command_handle->re_transmit_timer_private_data.file_descriptor = timer_fd;
        command_handle->re_transmit_timer_private_data.callback = on_timer_expired;

        epoll_register(&command_handle->re_transmit_timer_private_data);
      } else if (command_handle->error_status == SL_STATUS_IN_PROGRESS) {
        // Simply restart the timer
        ret = timerfd_settime(command_handle->re_transmit_timer_private_data.file_descriptor, 0, &timeout, NULL);
        FATAL_SYSCALL_ON(ret < 0);
      } else {
        WARN("Received ACK on a command that timed out or is processed.. ignoring");
      }

      command_handle->acked = true;

      return; // Found the associated command
    }
  }

  WARN("Received a system poll ack for which no pending poll is registered");
}

/***************************************************************************//**
 * Send no-operation command query
 ******************************************************************************/
void sl_cpc_system_cmd_noop(sl_cpc_system_noop_cmd_callback_t on_noop_reply,
                            uint8_t retry_count_max,
                            uint32_t retry_timeout_us)
{
  sl_cpc_system_command_handle_t *command_handle;

  /* Malloc the command handle and the command buffer */
  {
    command_handle = zalloc(sizeof(sl_cpc_system_command_handle_t));
    FATAL_ON(command_handle == NULL);

    command_handle->command = zalloc(sizeof(sl_cpc_system_cmd_t)); //noop had nothing in the 'payload field'
    FATAL_ON(command_handle->command == NULL);
  }

  sl_cpc_system_init_command_handle(command_handle, (void*)on_noop_reply, retry_count_max,
                                    retry_timeout_us, false);

  /* Fill the system endpoint command buffer */
  {
    sl_cpc_system_cmd_t *tx_command = command_handle->command;

    tx_command->command_id = CMD_SYSTEM_NOOP;
    tx_command->command_seq = command_handle->command_seq;
    tx_command->length = 0;
  }

  write_command(command_handle);

  TRACE_SYSTEM("NOOP (id #%u) sent", CMD_SYSTEM_NOOP);
}

/***************************************************************************//**
 * Send a reboot query
 ******************************************************************************/
void sl_cpc_system_cmd_reboot(sl_cpc_system_reset_cmd_callback_t on_reset_reply,
                              uint8_t retry_count_max,
                              uint32_t retry_timeout_us)
{
  sl_cpc_system_command_handle_t *command_handle;

  /* Malloc the command handle and the command buffer */
  {
    command_handle = zalloc(sizeof(sl_cpc_system_command_handle_t));
    FATAL_ON(command_handle == NULL);

    command_handle->command = zalloc(sizeof(sl_cpc_system_cmd_t)); //reset had nothing in the 'payload field'
    FATAL_ON(command_handle->command == NULL);
  }

  sl_cpc_system_init_command_handle(command_handle, (void*)on_reset_reply, retry_count_max,
                                    retry_timeout_us, true);

  /* Fill the system endpoint command buffer */
  {
    sl_cpc_system_cmd_t *tx_command = command_handle->command;

    tx_command->command_id = CMD_SYSTEM_RESET;
    tx_command->command_seq = command_handle->command_seq;
    tx_command->length = 0;
  }

  write_command(command_handle);

  TRACE_SYSTEM("reset (id #%u) sent", CMD_SYSTEM_RESET);
}

/***************************************************************************//**
 * Check if the system endpoint received a previously requested unnumered acknowledgement
 ******************************************************************************/
bool sl_cpc_system_received_unnumbered_acknowledgement(void)
{
  return received_remote_sequence_numbers_reset_ack;
}

/***************************************************************************//**
 * Acknowledge the reset sequence numbers on the secondary
 ******************************************************************************/
void sl_cpc_system_on_unnumbered_acknowledgement(void)
{
  sl_slist_node_t *item;
  sl_cpc_system_command_handle_t *command_handle;

  TRACE_SYSTEM("Received sequence numbers reset acknowledgement");
  received_remote_sequence_numbers_reset_ack = true;

  // Send any pending commands
  item = sl_slist_pop(&pending_commands);
  while (item != NULL) {
    command_handle = SL_SLIST_ENTRY(item, sl_cpc_system_command_handle_t, node_commands);
    write_command(command_handle);
    item = sl_slist_pop(&pending_commands);
  }
}

/***************************************************************************//**
 * Callback for the unnumered acknowledge timeout
 ******************************************************************************/
static void on_unnumbered_acknowledgement_timeout(epoll_private_data_t *private_data)
{
  sl_slist_node_t *item;
  int timer_fd = private_data->file_descriptor;
  sl_cpc_system_command_handle_t *command_handle = container_of(private_data,
                                                                sl_cpc_system_command_handle_t,
                                                                re_transmit_timer_private_data);

  if (sl_cpc_system_received_unnumbered_acknowledgement()) {
    // Unnumbered ack was processed, stop the timeout timer
    if (command_handle->re_transmit_timer_private_data.file_descriptor != 0) {
      epoll_unregister(&command_handle->re_transmit_timer_private_data);
      close(command_handle->re_transmit_timer_private_data.file_descriptor);
      command_handle->re_transmit_timer_private_data.file_descriptor = 0;
    }
    return;
  }

  TRACE_SYSTEM("Remote is unresponsive, retrying...");

  /* Ack the timer */
  {
    uint64_t expiration;
    ssize_t retval;

    retval = read(timer_fd, &expiration, sizeof(expiration));

    FATAL_SYSCALL_ON(retval < 0);

    FATAL_ON(retval != sizeof(expiration));

    WARN_ON(expiration != 1); /* we missed a timeout*/
  }

  /* Drop any pending commands to prevent accumulation*/
  item = sl_slist_pop(&pending_commands);
  while (item != NULL) {
    command_handle = SL_SLIST_ENTRY(item, sl_cpc_system_command_handle_t, node_commands);

    if (command_handle->command->command_id != CMD_SYSTEM_INVALID) {
      sl_cpc_system_cmd_abort(command_handle, SL_STATUS_ABORT);
    }
    free(command_handle->command);
    free(command_handle);
    item = sl_slist_pop(&pending_commands);
  }

  core_write(SL_CPC_ENDPOINT_SYSTEM, NULL, 0, SL_CPC_FLAG_UNNUMBERED_RESET_COMMAND);
}

/***************************************************************************//**
 * Request that the secondary resets it's sequence numbers
 ******************************************************************************/
void sl_cpc_system_request_sequence_reset(void)
{
  int timer_fd, ret;
  sl_cpc_system_command_handle_t *command_handle;

  sl_cpc_system_reset_system_endpoint();

  TRACE_SYSTEM("Requesting reset of sequence numbers on the remote");
  core_write(SL_CPC_ENDPOINT_SYSTEM, NULL, 0, SL_CPC_FLAG_UNNUMBERED_RESET_COMMAND);

  // Push the command right away
  core_process_transmit_queue();

  // Register a timeout timer in case we don't receive an unnumbered acknowledgement
  const struct itimerspec timeout = { .it_interval = { .tv_sec = UNNUMBERED_ACK_TIMEOUT_SECONDS, .tv_nsec = 0 },
                                      .it_value    = { .tv_sec = UNNUMBERED_ACK_TIMEOUT_SECONDS, .tv_nsec = 0 } };

  timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);

  FATAL_SYSCALL_ON(timer_fd < 0);

  ret = timerfd_settime(timer_fd, 0, &timeout, NULL);
  FATAL_SYSCALL_ON(ret < 0);

  command_handle = zalloc(sizeof(sl_cpc_system_command_handle_t));
  FATAL_ON(command_handle == NULL);

  /* Setup the timer in the server_core epoll set */
  command_handle->re_transmit_timer_private_data.file_descriptor = timer_fd;
  command_handle->re_transmit_timer_private_data.callback = on_unnumbered_acknowledgement_timeout;

  epoll_register(&command_handle->re_transmit_timer_private_data);

  ret = timerfd_settime(command_handle->re_transmit_timer_private_data.file_descriptor, 0, &timeout, NULL);
  FATAL_SYSCALL_ON(ret < 0);

  received_remote_sequence_numbers_reset_ack = false;
}

/***************************************************************************//**
 * Reset the system endpoint
 ******************************************************************************/
void sl_cpc_system_reset_system_endpoint(void)
{
  sl_slist_node_t *item;
  sl_cpc_system_command_handle_t *command_handle;

  // Abort any pending commands
  item = sl_slist_pop(&commands);
  while (item != NULL) {
    command_handle = SL_SLIST_ENTRY(item, sl_cpc_system_command_handle_t, node_commands);

    if (command_handle->command->command_id != CMD_SYSTEM_INVALID) {
      WARN("Dropping system command id #%d seq#%d", command_handle->command->command_id, command_handle->command_seq);
      sl_cpc_system_cmd_abort(command_handle, SL_STATUS_ABORT);
    }

    // Command payload will be freed once we close the endpoint
    free(command_handle->command);
    free(command_handle);
    item = sl_slist_pop(&commands);
  }

  // Close the system endpoint
  core_close_endpoint(SL_CPC_ENDPOINT_SYSTEM, false, true);

  // Re-open the system endpoint
  sl_cpc_system_open_endpoint();
}

/***************************************************************************//**
 * Send a property-get query
 ******************************************************************************/
void sl_cpc_system_cmd_property_get(sl_cpc_system_property_get_set_cmd_callback_t on_property_get_reply,
                                    sl_cpc_property_id_t property_id,
                                    uint8_t retry_count_max,
                                    uint32_t retry_timeout_us,
                                    bool is_uframe)
{
  sl_cpc_system_command_handle_t *command_handle;

  /* Malloc the command handle and the command buffer */
  {
    const size_t property_get_buffer_size = sizeof(sl_cpc_system_cmd_t) + sizeof(sl_cpc_property_id_t);

    command_handle = zalloc(sizeof(sl_cpc_system_command_handle_t));
    FATAL_ON(command_handle == NULL);

    // Allocate a buffer and pad it to 8 bytes because memcpy reads in chunks of 8.
    // If we don't pad, Valgrind will complain.
    command_handle->command = zalloc(PAD_TO_8_BYTES(property_get_buffer_size)); //property-get has the property id as payload
    FATAL_ON(command_handle->command == NULL);
  }

  sl_cpc_system_init_command_handle(command_handle, (void*)on_property_get_reply, retry_count_max,
                                    retry_timeout_us, is_uframe);

  /* Fill the system endpoint command buffer */
  {
    sl_cpc_system_cmd_t *tx_command = command_handle->command;
    sl_cpc_system_property_cmd_t *tx_property_command = (sl_cpc_system_property_cmd_t *) tx_command->payload;

    tx_command->command_id = CMD_SYSTEM_PROP_VALUE_GET;
    tx_command->command_seq = command_handle->command_seq;
    tx_property_command->property_id = cpu_to_le32(property_id);
    tx_command->length = sizeof(sl_cpc_property_id_t);
  }

  write_command(command_handle);

  TRACE_SYSTEM("property-get (id #%u) sent with property 0x%x", CMD_SYSTEM_PROP_VALUE_GET, property_id);
}

/***************************************************************************//**
 * Send a property-set query
 ******************************************************************************/
void sl_cpc_system_cmd_property_set(sl_cpc_system_property_get_set_cmd_callback_t on_property_set_reply,
                                    uint8_t retry_count_max,
                                    uint32_t retry_timeout_us,
                                    sl_cpc_property_id_t property_id,
                                    const void *value,
                                    size_t value_length,
                                    bool is_uframe)
{
  sl_cpc_system_command_handle_t *command_handle;

  BUG_ON(on_property_set_reply == NULL);

  {
    const size_t property_get_buffer_size = sizeof(sl_cpc_system_cmd_t) + sizeof(sl_cpc_property_id_t) + value_length;

    command_handle = zalloc(sizeof(sl_cpc_system_command_handle_t));
    FATAL_ON(command_handle == NULL);

    // Allocate a buffer and pad it to 8 bytes because memcpy reads in chunks of 8.
    // If we don't pad, Valgrind will complain.
    command_handle->command = zalloc(PAD_TO_8_BYTES(property_get_buffer_size)); //property-get has the property id as payload
    FATAL_ON(command_handle->command == NULL);
  }

  sl_cpc_system_init_command_handle(command_handle, (void *)on_property_set_reply,
                                    retry_count_max, retry_timeout_us, is_uframe);

  /* Fill the system endpoint command buffer */
  {
    sl_cpc_system_cmd_t *tx_command = command_handle->command;
    sl_cpc_system_property_cmd_t *tx_property_command = (sl_cpc_system_property_cmd_t *) tx_command->payload;;

    tx_command->command_id = CMD_SYSTEM_PROP_VALUE_SET;
    tx_command->command_seq = command_handle->command_seq;
    tx_property_command->property_id = cpu_to_le32(property_id);

    /* Adapt the property value in function of the endianess of the system.
     * We make the assumption here that if a property's length value is 2, 4 or 8 then
     * we wanted to send a property value that was a u/int16_t, a u/int32_t or a u/int64_t
     * respectively to begin with. System endpoint protocol doesn't have any other properties that have
     * length other than those anyway (plus then unit 1 byte length, which doesn't need endianness
     * awareness anyway). */
    {
      switch (value_length) {
        case 0:
          FATAL("Can't send a property-set request with value of length 0");
          break;

        case 1:
          memcpy(tx_property_command->payload, value, value_length);
          break;

        case 2:
        {
          uint16_t le16 = cpu_to_le16p((uint16_t*)value);
          memcpy(tx_property_command->payload, &le16, 2);
        }
        break;

        case 4:
        {
          uint32_t le32 = cpu_to_le32p((uint32_t*)value);
          memcpy(tx_property_command->payload, &le32, 4);
        }
        break;

        case 8:
        {
          uint64_t le64 = cpu_to_le64p((uint64_t*)value);
          memcpy(tx_property_command->payload, &le64, 8);
        }
        break;

        default:
          memcpy(tx_property_command->payload, value, value_length);
          break;
      }
    }

    tx_command->length = (uint8_t)(sizeof(sl_cpc_property_id_t) + value_length);
  }

  write_command(command_handle);

  TRACE_SYSTEM("property-set (id #%u) sent with property #%u", CMD_SYSTEM_PROP_VALUE_SET, property_id);
}

/***************************************************************************//**
 * Handle no-op from SECONDARY:
 *   This functions is called when a no-op command is received from the SECONDARY.
 *   The SECONDARY will send back a no-op in response to the one sent by the PRIMARY.
 ******************************************************************************/
static void on_final_noop(sl_cpc_system_command_handle_t *command_handle,
                          sl_cpc_system_cmd_t *system_cmd,
                          const uint8_t *system_cmd_payload,
                          size_t system_cmd_payload_length)
{
  (void)system_cmd, (void)system_cmd_payload, (void)system_cmd_payload_length;

  TRACE_SYSTEM("on_final_noop()");

  ((sl_cpc_system_noop_cmd_callback_t)command_handle->on_final)(command_handle,
                                                                command_handle->error_status);
}

/***************************************************************************//**
 * Handle reset from SECONDARY:
 *   This functions is called when a reset command is received from the SECONDARY.
 *   The SECONDARY will send back a reset in response to the one sent by the PRIMARY.
 ******************************************************************************/
static void on_final_reset(sl_cpc_system_command_handle_t * command_handle,
                           const uint8_t *system_cmd_payload,
                           size_t system_cmd_payload_length)
{
  TRACE_SYSTEM("on_final_reset()");

  ignore_reset_reason = false;

  // Deal with endianness of the returned status since its a 32bit value.
  sl_cpc_system_status_t reset_status_le, reset_status_cpu;

  reset_status_le = 0;
  memcpy(&reset_status_le, system_cmd_payload,
         min(system_cmd_payload_length, sizeof(reset_status_le)));
  reset_status_cpu = le32_to_cpu(reset_status_le);

  ((sl_cpc_system_reset_cmd_callback_t)command_handle->on_final)(command_handle,
                                                                 command_handle->error_status,
                                                                 reset_status_cpu);
}

/***************************************************************************//**
 * Handle property-is from SECONDARY:
 *   This functions is called when a property-is command is received from the SECONDARY.
 *   The SECONDARY emits a property-is in response to a property-get/set.
 ******************************************************************************/
static void on_final_property_is(sl_cpc_system_command_handle_t * command_handle,
                                 sl_cpc_system_cmd_t *system_cmd,
                                 const uint8_t *system_cmd_payload,
                                 size_t system_cmd_payload_length,
                                 bool is_uframe)
{
  sl_cpc_system_property_get_set_cmd_callback_t callback = (sl_cpc_system_property_get_set_cmd_callback_t)command_handle->on_final;

  sl_cpc_system_property_cmd_t system_property_cmd;
  const uint8_t *system_property_cmd_payload;

  memset(&system_property_cmd, 0, sizeof(system_property_cmd));
  memcpy(&system_property_cmd, system_cmd_payload,
         min(system_cmd_payload_length, sizeof(system_property_cmd)));
  system_property_cmd_payload = system_cmd_payload + sizeof(system_property_cmd);

  // Make sure only certain properties are allowed as u-frame (non-encrypted)
  if (is_uframe) {
    // Should not allow unecrypted responses when security isn't disabled to
    // protect from brute-force attacks.
#if defined(ENABLE_ENCRYPTION)
    sl_cpc_security_state_t security_state = security_get_state();
    if (config.use_encryption && security_state == SECURITY_STATE_INITIALIZED) {
      FATAL("Received on_final property_is %x as a u-frame when security was enabled.", system_property_cmd.property_id);
    }
#endif // ENABLE_ENCRYPTION
    switch (system_property_cmd.property_id) {
      case PROP_RX_CAPABILITY:
      case PROP_CAPABILITIES:
      case PROP_BUS_BITRATE_VALUE:
      case PROP_BUS_MAX_BITRATE_VALUE:
      case PROP_PROTOCOL_VERSION:
      case PROP_BOOTLOADER_INFO:
      case PROP_SECONDARY_CPC_VERSION:
      case PROP_SECONDARY_APP_VERSION:
      case PROP_BOOTLOADER_REBOOT_MODE:
      case PROP_LAST_STATUS:
        break;
      default:
        FATAL("Received on_final property_is %x as a u-frame", system_property_cmd.property_id);
        break;
    }
  }

  /* Deal with endianness of the returned property-id since its a 32bit value. */
  sl_cpc_property_id_t property_id_le = system_property_cmd.property_id;
  sl_cpc_property_id_t property_id_cpu = le32_to_cpu(property_id_le);

  size_t value_length = system_cmd->length - sizeof(sl_cpc_system_property_cmd_t);

  callback(command_handle,
           property_id_cpu,
           (uint8_t *)system_property_cmd_payload, /* discard const qualifier */
           value_length,
           command_handle->error_status);
}

/***************************************************************************//**
 * This function is called by CPC core poll reply (final) is received
 ******************************************************************************/
static void on_reply(uint8_t endpoint_id,
                     void *arg,
                     void *answer,
                     uint32_t answer_lenght)
{
  sl_cpc_system_command_handle_t *command_handle;
  size_t frame_type = (size_t)arg;
  const uint8_t *frame_payload;
  sl_cpc_system_cmd_t system_cmd;
  const uint8_t *system_cmd_payload;
  size_t system_cmd_payload_length;

  frame_payload = (const uint8_t *)answer;

  memcpy(&system_cmd, frame_payload, sizeof(system_cmd));
  system_cmd_payload = frame_payload + sizeof(system_cmd);
  system_cmd_payload_length = answer_lenght - sizeof(system_cmd);

  BUG_ON(endpoint_id != 0);
  FATAL_ON(system_cmd.length != system_cmd_payload_length);

  /* Go through the list of pending requests to find the one for which this reply applies */
  SL_SLIST_FOR_EACH_ENTRY(commands, command_handle, sl_cpc_system_command_handle_t, node_commands) {
    if (command_handle->command_seq == system_cmd.command_seq) {
      TRACE_SYSTEM("Processing command seq#%d of type %d", system_cmd.command_seq, frame_type);

      /* Stop and close the retransmit timer */
      if (frame_type == SLI_CPC_HDLC_FRAME_TYPE_UNNUMBERED
          || (frame_type == SLI_CPC_HDLC_FRAME_TYPE_INFORMATION && command_handle->acked == true)) {
        BUG_ON(command_handle->re_transmit_timer_private_data.file_descriptor <= 0);
        epoll_unregister(&command_handle->re_transmit_timer_private_data);
        close(command_handle->re_transmit_timer_private_data.file_descriptor);
        command_handle->re_transmit_timer_private_data.file_descriptor = 0;
      }

      /* Call the appropriate callback */
      if (frame_type == SLI_CPC_HDLC_FRAME_TYPE_UNNUMBERED) {
        BUG_ON(command_handle->is_uframe == false);
        switch (system_cmd.command_id) {
          case CMD_SYSTEM_RESET:
            on_final_reset(command_handle, system_cmd_payload, system_cmd_payload_length);
            break;
          case CMD_SYSTEM_PROP_VALUE_IS:
            on_final_property_is(command_handle, &system_cmd, system_cmd_payload, system_cmd_payload_length, true);
            break;
          default:
            FATAL("system endpoint command id not recognized for u-frame");
            break;
        }
      } else if (frame_type == SLI_CPC_HDLC_FRAME_TYPE_INFORMATION) {
        BUG_ON(command_handle->is_uframe == true);
        switch (system_cmd.command_id) {
          case CMD_SYSTEM_NOOP:
            on_final_noop(command_handle, &system_cmd, system_cmd_payload, system_cmd_payload_length);
            break;

          case CMD_SYSTEM_PROP_VALUE_IS:
            on_final_property_is(command_handle, &system_cmd, system_cmd_payload, system_cmd_payload_length, false);
            break;

          case CMD_SYSTEM_PROP_VALUE_GET:
          case CMD_SYSTEM_PROP_VALUE_SET:
            FATAL("its the primary who sends those");
            break;

          default:
            FATAL("system endpoint command id not recognized for i-frame");
            break;
        }
      } else {
        FATAL("Invalid frame_type");
      }

      /* Cleanup this command now that it's been serviced */
      sl_slist_remove(&commands, &command_handle->node_commands);
      free(command_handle->command);
      free(command_handle);

      return;
    }
  }

  WARN("Received a system final for which no pending poll is registered");
}

static void on_uframe_receive(uint8_t endpoint_id, const void* data, size_t data_len)
{
  FATAL_ON(endpoint_id != SL_CPC_ENDPOINT_SYSTEM);

  TRACE_SYSTEM("Unsolicited uframe received");

#if defined(TARGET_TESTING)
  PRINT_INFO("STATUS_OK\n");
#endif

  if (data_len < sizeof(sl_cpc_system_cmd_t)) {
    WARN("System endpoint received a uframe with not enough bytes to properly parse");
    return;
  }

  sl_cpc_system_cmd_t *reply = (sl_cpc_system_cmd_t *)data;

  if (reply->length != data_len - sizeof(sl_cpc_system_cmd_t)) {
    WARN("Invalid system endpoint command length, ignoring frame");
    return;
  }

  if (reply->command_id == CMD_SYSTEM_PROP_VALUE_IS) {
    sl_cpc_system_property_cmd_t *property = (sl_cpc_system_property_cmd_t*) reply->payload;

    if (property->property_id == PROP_LAST_STATUS) {
      prop_last_status_callback_list_item_t *item;

      SL_SLIST_FOR_EACH_ENTRY(prop_last_status_callbacks, item, prop_last_status_callback_list_item_t, node) {
        sl_cpc_system_status_t* status = (sl_cpc_system_status_t*) property->payload;

        item->callback(*status);
      }
    }
  }
}

static void on_iframe_unsolicited(uint8_t endpoint_id, const void* data, size_t data_len)
{
  FATAL_ON(endpoint_id != SL_CPC_ENDPOINT_SYSTEM);

  TRACE_SYSTEM("Unsolicited i-frame received");

  if (server_core_reset_sequence_in_progress()) {
    TRACE_SYSTEM("Cannot process unsolicited i-frame during reset sequence, ignoring");
    return;
  }

  sl_cpc_system_cmd_t *reply = (sl_cpc_system_cmd_t *)data;

  FATAL_ON(reply->length != data_len - sizeof(sl_cpc_system_cmd_t));

  if (reply->command_id == CMD_SYSTEM_PROP_VALUE_IS) {
    sl_cpc_system_property_cmd_t *property = (sl_cpc_system_property_cmd_t*) reply->payload;

    if (property->property_id >= PROP_ENDPOINT_STATE_0 && property->property_id <= PROP_ENDPOINT_STATE_255) {
      uint8_t closed_endpoint_id = PROPERTY_ID_TO_EP_ID(property->property_id);
      cpc_endpoint_state_t endpoint_state = core_state_mapper(*(uint8_t*)property->payload);

      if (endpoint_state == SL_CPC_STATE_CLOSING) {
        TRACE_SYSTEM("Secondary closed the endpoint #%d", closed_endpoint_id);
        // The secondary notified us this endpoint will be closed
        if (!server_listener_list_empty(closed_endpoint_id) && core_get_endpoint_state(closed_endpoint_id) == SL_CPC_STATE_OPEN) {
          // There are still clients connected to the endpoint
          // We set this endpoint in error so clients are aware
          core_set_endpoint_in_error(closed_endpoint_id, SL_CPC_STATE_ERROR_DESTINATION_UNREACHABLE);
          // And we acknowledge this notification
          sl_cpc_system_cmd_property_set(reply_to_closing_endpoint_on_secondary_async_callback,
                                         ENDPOINT_CLOSE_RETRIES,
                                         ENDPOINT_CLOSE_RETRY_TIMEOUT,
                                         property->property_id,
                                         &endpoint_state,
                                         sizeof(cpc_endpoint_state_t),
                                         false);
        } else {
          // We acknowledge this notification and close the endpoint in the callback
          sl_cpc_system_cmd_property_set(reply_to_closing_endpoint_on_secondary_callback,
                                         ENDPOINT_CLOSE_RETRIES,
                                         ENDPOINT_CLOSE_RETRY_TIMEOUT,
                                         property->property_id,
                                         &endpoint_state,
                                         sizeof(cpc_endpoint_state_t),
                                         false);
        }
      } else {
        FATAL("Invalid property id");
      }
    }
  }
}

/***************************************************************************//**
 * System endpoint timer expire callback
 ******************************************************************************/
static void on_timer_expired(epoll_private_data_t *private_data)
{
  int timer_fd = private_data->file_descriptor;
  sl_cpc_system_command_handle_t *command_handle = container_of(private_data,
                                                                sl_cpc_system_command_handle_t,
                                                                re_transmit_timer_private_data);

  TRACE_SYSTEM("Command ID #%u SEQ #%u timer expired", command_handle->command->command_id, command_handle->command->command_seq);

  /* Ack the timer */
  {
    uint64_t expiration;
    ssize_t retval;

    retval = read(timer_fd, &expiration, sizeof(expiration));

    FATAL_SYSCALL_ON(retval < 0);

    FATAL_ON(retval != sizeof(expiration));

    WARN_ON(expiration != 1); /* we missed a timeout*/
  }

  if (!command_handle->retry_forever) {
    command_handle->retry_count--;
  }

  if (command_handle->retry_count > 0 || command_handle->retry_forever) {
    sl_slist_remove(&commands, &command_handle->node_commands);

    command_handle->error_status = SL_STATUS_IN_PROGRESS; //at least one timer retry occurred

    write_command(command_handle);

    if (command_handle->retry_forever) {
      TRACE_SYSTEM("Command ID #%u SEQ #%u retried", command_handle->command->command_id, command_handle->command->command_seq);
    } else {
      TRACE_SYSTEM("Command ID #%u SEQ #%u. %u retry left", command_handle->command->command_id, command_handle->command->command_seq, command_handle->retry_count);
    }
  } else {
    sl_cpc_system_cmd_timed_out(command_handle->command);
  }
}

/***************************************************************************//**
 * Write command on endpoint
 ******************************************************************************/
static void write_command(sl_cpc_system_command_handle_t *command_handle)
{
  int timer_fd;
  uint8_t flags = SL_CPC_FLAG_INFORMATION_POLL;

  if (command_handle->retry_count == 0) {
    command_handle->retry_forever = true;
  } else {
    command_handle->retry_forever = false;
  }

  if (command_handle->is_uframe) {
    flags = SL_CPC_FLAG_UNNUMBERED_POLL;
  }

#if !defined(UNIT_TESTING)
  // Can't send iframe commands on the system endpoint until the sequence numbers are reset
  if (!command_handle->is_uframe) {
    if (!sl_cpc_system_received_unnumbered_acknowledgement()) {
      sl_slist_push_back(&pending_commands, &command_handle->node_commands);
      return;
    }
  }
#endif

  sl_slist_push_back(&commands, &command_handle->node_commands);

  command_handle->acked = false;

  core_write(SL_CPC_ENDPOINT_SYSTEM,
             (void *)command_handle->command,
             SIZEOF_SYSTEM_COMMAND(command_handle->command),
             flags);

  TRACE_SYSTEM("Submitted command_id #%d command_seq #%d", command_handle->command->command_id, command_handle->command_seq);

  if (command_handle->is_uframe) {
    /* Setup timeout timer.*/
    {
      const struct itimerspec timeout = { .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
                                          .it_value    = { .tv_sec = (long int)command_handle->retry_timeout_us / 1000000, .tv_nsec = ((long int)command_handle->retry_timeout_us * 1000) % 1000000000 } };

      timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);

      FATAL_SYSCALL_ON(timer_fd < 0);

      int ret = timerfd_settime(timer_fd,
                                0,
                                &timeout,
                                NULL);

      FATAL_SYSCALL_ON(ret < 0);
    }

    /* Setup the timer in the server_core epoll set */
    {
      command_handle->re_transmit_timer_private_data.endpoint_number = SL_CPC_ENDPOINT_SYSTEM;
      command_handle->re_transmit_timer_private_data.file_descriptor = timer_fd;
      command_handle->re_transmit_timer_private_data.callback = on_timer_expired;

      epoll_register(&command_handle->re_transmit_timer_private_data);
    }
  }
}

void sl_cpc_system_cleanup(void)
{
  sl_slist_node_t *item;
  prop_last_status_callback_list_item_t *callback_list_item;

  TRACE_RESET("Server core cleanup");

  item = sl_slist_pop(&prop_last_status_callbacks);
  while (item != NULL) {
    callback_list_item = SL_SLIST_ENTRY(item, prop_last_status_callback_list_item_t, node);
    free(callback_list_item);
    item = sl_slist_pop(&pending_commands);
  }

  // Close the system endpoint
  core_close_endpoint(SL_CPC_ENDPOINT_SYSTEM, false, true);
}
