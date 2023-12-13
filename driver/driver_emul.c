/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Emulation driver
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

#define _GNU_SOURCE
#include <pthread.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "cpcd/core.h"
#include "cpcd/logging.h"
#include "cpcd/security.h"
#include "cpcd/sl_slist.h"
#include "cpcd/sl_status.h"
#include "cpcd/utils.h"

#include "driver/driver_emul.h"
#include "server_core/core/crc.h"
#include "server_core/core/hdlc.h"
#include "server_core/system_endpoint/system.h"
#include "security/security.h"
#include "security/private/keys/keys.h"
#include "test/unity/cpc_unity_common.h"

static int fd_socket_drv;
static int fd_notification_socket_drv;
static pthread_t drv_thread;
static sl_slist_node_t *sli_rx_pending_list_head;
static sli_cpc_endpoint_state_t ep_states[SL_CPC_ENDPOINT_MAX_COUNT];
static uint32_t ep_frame_counters_tx[SL_CPC_ENDPOINT_MAX_COUNT];
static uint32_t ep_frame_counters_rx[SL_CPC_ENDPOINT_MAX_COUNT];

typedef struct {
  sl_slist_node_t node;
  frame_t *buf_handle;
  uint16_t payload_len;
} sli_buf_entry_rx;

static void* driver_thread_func(void* param);

pthread_t driver_emul_init(int* fd_core, int *fd_notify_core)
{
  int fd_sockets[2];
  int fd_notify_sockets[2];
  uint32_t i;

  sl_slist_init(&sli_rx_pending_list_head);

  if (0 != socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets)) {
    FATAL("Create driver socket pair : %m");
  }

  fd_socket_drv  = fd_sockets[0];

  /* create driver thread */
  if (pthread_create(&drv_thread, NULL, driver_thread_func, NULL)) {
    FATAL("Error creating driver thread");
  }

  for (i = 0; i < SL_CPC_ENDPOINT_MAX_COUNT; i++) {
    ep_states[i] = SLI_CPC_STATE_OPEN;
  }

  *fd_core = fd_sockets[1];

  if (0 != socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_notify_sockets)) {
    FATAL("Create driver notification socket pair : %m");
  }

  fd_notification_socket_drv  = fd_notify_sockets[0];
  *fd_notify_core = fd_notify_sockets[1];

  return drv_thread;
}

// -----------------------------------------------------------------------------
// Validation interface
sli_cpc_endpoint_state_t sli_cpc_drv_emul_get_ep_state(uint8_t id)
{
  return ep_states[id];
}

void sli_cpc_drv_emul_set_ep_state(uint8_t id, sli_cpc_endpoint_state_t state)
{
  FATAL_ON(id == 0);
  ep_states[id] = state;
  TRACE_DRIVER("Externally setting state of ep #%d to state %d",
               id, ep_states[id]);
}

void sli_cpc_drv_emul_set_frame_counter(uint8_t id, uint32_t frame_counter, bool tx)
{
  if (tx) {
    ep_frame_counters_tx[id] = frame_counter;
  } else {
    ep_frame_counters_rx[id] = frame_counter;
  }
}

uint32_t sli_cpc_drv_emul_get_frame_counter(uint8_t id, bool tx)
{
  if (tx) {
    return ep_frame_counters_tx[id];
  } else {
    return ep_frame_counters_rx[id];
  }
}

void sli_cpc_drv_emul_submit_pkt_for_rx(void *header_buf, void *payload_buf, uint16_t payload_buf_len)
{
  uint8_t *buffer;
  uint16_t tag_len = 0;
#if defined(ENABLE_ENCRYPTION)
  sl_cpc_security_state_t security_state = security_get_state();
  uint8_t control = hdlc_get_control(header_buf);
  uint8_t address = hdlc_get_address(header_buf);
  uint8_t type = hdlc_get_frame_type(control);

  // set tag_len to non-zero value if frame should be encrypted
  if (security_state == SECURITY_STATE_INITIALIZED
      && type == SLI_CPC_HDLC_FRAME_TYPE_INFORMATION
      && payload_buf_len > 2
      && address != SL_CPC_ENDPOINT_SECURITY) {
    tag_len = (uint16_t)__security_encrypt_get_extra_buffer_size();
  }
#endif

  buffer = (uint8_t *)zalloc(SLI_CPC_HDLC_HEADER_RAW_SIZE + payload_buf_len + tag_len);
  FATAL_ON(buffer == NULL);

  if (buffer == NULL) {
    return;
  }

  if (tag_len) {
#if defined(ENABLE_ENCRYPTION)
    sl_cpc_endpoint_t endpoint;
    sl_status_t status;
    uint16_t fcs;
    uint8_t ack;

    // recreate header with adjusted tag length
    hdlc_create_header(buffer,
                       address,
                       hdlc_get_length(header_buf) + tag_len,
                       hdlc_get_control(header_buf),
                       true);

    // FCS is part of payload_buf_len, drop it as it's useless to us now
    payload_buf_len -= 2;

    endpoint.id = hdlc_get_address(header_buf);
    endpoint.frame_counter_tx = ep_frame_counters_tx[endpoint.id];

    ack = hdlc_get_ack(hdlc_get_control(buffer));
    hdlc_set_control_ack(&buffer[SLI_CPC_HDLC_CONTROL_POS], 0);

    status = __security_encrypt_secondary(&endpoint,
                                          buffer, SLI_CPC_HDLC_HEADER_SIZE,
                                          payload_buf, payload_buf_len,
                                          &buffer[SLI_CPC_HDLC_HEADER_RAW_SIZE],
                                          &buffer[SLI_CPC_HDLC_HEADER_RAW_SIZE + payload_buf_len], tag_len);

    if (status != SL_STATUS_OK) {
      perror("Failed to emulate frame encryption on secondary");
      return;
    }

    hdlc_set_control_ack(&buffer[SLI_CPC_HDLC_CONTROL_POS], ack);

    ep_frame_counters_tx[endpoint.id] = endpoint.frame_counter_tx;

    // recompute FCS with encrypted payload + tag
    fcs = sli_cpc_get_crc_sw(&buffer[SLI_CPC_HDLC_HEADER_RAW_SIZE],
                             payload_buf_len + tag_len);
    buffer[SLI_CPC_HDLC_HEADER_RAW_SIZE + payload_buf_len + tag_len + 0] = (uint8_t)fcs;
    buffer[SLI_CPC_HDLC_HEADER_RAW_SIZE + payload_buf_len + tag_len + 1] = (uint8_t)(fcs >> 8);

    // restore payload_buf_len to accomodate "send"
    payload_buf_len += 2;
#endif
  } else {
    memcpy(buffer, header_buf, SLI_CPC_HDLC_HEADER_RAW_SIZE);
    if (payload_buf_len > 0) {
      memcpy(&buffer[SLI_CPC_HDLC_HEADER_RAW_SIZE], payload_buf, payload_buf_len);
    }
  }

  (void)send(fd_socket_drv, buffer, payload_buf_len + tag_len + SLI_CPC_HDLC_HEADER_RAW_SIZE, 0);

  free(buffer);
}

static void sli_cpc_drv_emul_create_get_endpoint_property(sli_cpc_system_cmd_t *tx_command,
                                                          sli_cpc_property_id_t prop_id,
                                                          uint8_t command_seq)
{
  uint8_t ep_id = PROPERTY_ID_TO_EP_ID(prop_id);

  if (prop_id >= EP_ID_TO_PROPERTY_STATE(0x00)
      && prop_id <= EP_ID_TO_PROPERTY_STATE(0xFF)) {
    sli_cpc_system_property_cmd_t *reply_prop_cmd_buff;
    sli_cpc_endpoint_state_t *reply_ep_state;

    TRACE_DRIVER("ep #%d is in state %d", ep_id, ep_states[ep_id]);

    FATAL_ON(tx_command == NULL);

    // Reply to a PROPERTY-GET with a PROPERTY-IS
    tx_command->command_id = CMD_SYSTEM_PROP_VALUE_IS;
    tx_command->command_seq = command_seq;

    reply_prop_cmd_buff = (sli_cpc_system_property_cmd_t*) tx_command->payload;
    reply_ep_state = (sli_cpc_endpoint_state_t*) reply_prop_cmd_buff->payload;

    reply_prop_cmd_buff->property_id = prop_id;

    *reply_ep_state = ep_states[ep_id];

    tx_command->length = sizeof(sli_cpc_property_id_t) + sizeof(sli_cpc_endpoint_state_t);
  } else if (prop_id >= EP_ID_TO_PROPERTY_ENCRYPTION(0x00)
             && prop_id <= EP_ID_TO_PROPERTY_ENCRYPTION(0xFF)) {
    sli_cpc_system_property_cmd_t *reply_prop_cmd_buff;
    bool *reply_ep_encryption;

    TRACE_DRIVER("Checking encryption status for ep_id %d", ep_id);

    FATAL_ON(tx_command == NULL);

    // Reply to a PROPERTY-GET with a PROPERTY-IS
    tx_command->command_id = CMD_SYSTEM_PROP_VALUE_IS;
    tx_command->command_seq = command_seq;

    reply_prop_cmd_buff = (sli_cpc_system_property_cmd_t*) tx_command->payload;
    reply_ep_encryption = (bool*) reply_prop_cmd_buff->payload;

    reply_prop_cmd_buff->property_id = EP_ID_TO_PROPERTY_ENCRYPTION(ep_id);
    *reply_ep_encryption = true; // default to always encrypted

    tx_command->length = sizeof(sli_cpc_property_id_t) + sizeof(bool);
  }
}

static void sli_cpc_drv_emul_create_set_endpoint_status_reply(sli_cpc_system_cmd_t *tx_command, uint8_t ep_id, uint8_t command_seq, sli_cpc_endpoint_state_t state)
{
  FATAL_ON(tx_command == NULL);

  sli_cpc_system_property_cmd_t *reply_prop_cmd_buff;
  sli_cpc_endpoint_state_t *reply_ep_state;

  // Reply to a PROPERTY-GET with a PROPERTY-IS
  tx_command->command_id = CMD_SYSTEM_PROP_VALUE_IS;
  tx_command->command_seq = command_seq;

  reply_prop_cmd_buff = (sli_cpc_system_property_cmd_t*) tx_command->payload;
  reply_ep_state = (sli_cpc_endpoint_state_t*) reply_prop_cmd_buff->payload;

  reply_prop_cmd_buff->property_id = EP_ID_TO_PROPERTY_STATE(ep_id);

  *reply_ep_state = state;

  tx_command->length = sizeof(sli_cpc_property_id_t) + sizeof(sli_cpc_endpoint_state_t);
}

static void* driver_thread_func(void* param)
{
  (void)param;

  uint8_t temp_buffer[2048];
  fd_set rfds;
  int retval;
  ssize_t ret;
  frame_t *frame;
  int max_fd = 0;
  uint8_t control;
  uint8_t seq;
  uint8_t ack;
  uint8_t address;
  uint8_t  type;
#if defined(ENABLE_ENCRYPTION)
  sl_cpc_security_state_t security_state;
  uint8_t plaintext_buffer[2048];
  sl_cpc_endpoint_t endpoint;
  uint16_t length;
  uint16_t tag_len = (uint16_t)security_encrypt_get_extra_buffer_size();
#endif

  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

  while (1) {
    FD_ZERO(&rfds);
    FD_SET(fd_socket_drv, &rfds);
    max_fd = fd_socket_drv;
    /* select() requires the number of the highest file descriptor + 1 in the fd_set passed  */
    max_fd++;
    //no timeout
    retval = select(max_fd, &rfds, NULL, NULL, NULL);
    if (retval == -1) {
      perror("select()");
      continue;
    }
    if (FD_ISSET(fd_socket_drv, &rfds)) {
      memset(temp_buffer, 0, 2048);
      ret =  recv(fd_socket_drv, temp_buffer, 2048, 0);
      FATAL_ON(ret < 2);
      TRACE_DRIVER_RXD_FRAME((const void*)temp_buffer, (size_t)ret);

      // Notify core of TX completion
      struct timespec tx_complete_timestamp;
      clock_gettime(CLOCK_MONOTONIC, &tx_complete_timestamp);
      ssize_t write_retval = write(fd_notification_socket_drv, &tx_complete_timestamp, sizeof(tx_complete_timestamp));
      FATAL_SYSCALL_ON(write_retval != sizeof(tx_complete_timestamp));

      usleep(1000); // Add a delay to emulate the time it takes for the secondary to process the packet

      frame = (frame_t *)temp_buffer;
      control = hdlc_get_control(frame->header);
      address = hdlc_get_address(frame->header);
#if defined(ENABLE_ENCRYPTION)
      length  = hdlc_get_length(frame->header);
#endif
      type = hdlc_get_frame_type(control);
      seq = hdlc_get_seq(control);
      ack = hdlc_get_ack(control);

#if defined(ENABLE_ENCRYPTION)
      security_state = security_get_state();
      if (security_state == SECURITY_STATE_INITIALIZED
          && type == SLI_CPC_HDLC_FRAME_TYPE_INFORMATION
          && length > 0
          && address != SL_CPC_ENDPOINT_SECURITY) {
        sl_status_t status;
        uint8_t ack;

        /* the payload buffer must be longer than the security tag */
        BUG_ON(length < tag_len);
        length = (uint16_t)(length - tag_len - 2);

        endpoint.id = address;
        endpoint.frame_counter_rx = ep_frame_counters_rx[endpoint.id];

        ack = hdlc_get_ack(hdlc_get_control(frame->header));
        hdlc_set_control_ack(&frame->header[SLI_CPC_HDLC_CONTROL_POS], 0);

        /* decrypt like the secondary would do when receiving such frame */
        status = security_decrypt_secondary(&endpoint,
                                            frame->header, SLI_CPC_HDLC_HEADER_SIZE,
                                            frame->payload, length,
                                            plaintext_buffer,
                                            &(frame->payload[length]), tag_len);

        hdlc_set_control_ack(&frame->header[SLI_CPC_HDLC_CONTROL_POS], ack);

        ep_frame_counters_rx[endpoint.id] = endpoint.frame_counter_rx;

        if (status != SL_STATUS_OK) {
          TRACE_DRIVER("Failed to decrypt frame: 0x%x\n", status);
          continue;
        } else {
          TRACE_DRIVER("Successfully decrypted frame\n");
        }

        /* copy plaintext buffer at the payload pointer */
        memcpy(frame->payload, plaintext_buffer, length);
      }
#endif

      /* frame_t: | header[7] |              sl_cpc_system_cmd_t              |
       *                      | id | seq | len | sli_cpc_system_property_cmd_t |
       *                                       | prop_id |      payload       |
       *   0                   1                   2                   3
       *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |  header[7]  |i|s|len|prop_id|                                 |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                 :
       *  |                           payload                             |
       *  :                                                               :
       *  |                                                               |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       */
      const uint8_t *system_cmd_payload;
      sli_cpc_system_cmd_t system_cmd;
      const void *property_payload;
      uint16_t property_length;

      memcpy(&system_cmd, frame->payload, sizeof(system_cmd));

      /* system_cmd.payload cannot be used because it's a flexible array,
       * and its content is not copied by the memcpy */
      system_cmd_payload = frame->payload + sizeof(system_cmd);

      sli_cpc_system_property_cmd_t system_property_cmd;
      memcpy(&system_property_cmd, system_cmd_payload, sizeof(system_property_cmd));

      property_length = system_cmd.length - sizeof(sli_cpc_property_id_t);
      property_payload = frame->payload
                         + sizeof(sli_cpc_system_cmd_t)
                         + sizeof(sli_cpc_system_property_cmd_t);

      if (address == 0) {
        switch (system_cmd.command_id) {
          case CMD_SYSTEM_PROP_VALUE_GET:
          case CMD_SYSTEM_PROP_VALUE_SET:

            if ((system_property_cmd.property_id >= EP_ID_TO_PROPERTY_STATE(1)
                 && system_property_cmd.property_id <= EP_ID_TO_PROPERTY_STATE(255))
                || (system_property_cmd.property_id >= EP_ID_TO_PROPERTY_ENCRYPTION(1)
                    && system_property_cmd.property_id <= EP_ID_TO_PROPERTY_ENCRYPTION(255))) {
              TRACE_DRIVER("rxd frame ep#%d: seq=%d ack=%d", address, seq, ack);
              TRACE_DRIVER("received query for property 0x%x", system_property_cmd.property_id);
              uint8_t *buffer;
              size_t buf_len = 0;
              bool is_unnumbered;

              if (system_property_cmd.property_id >= EP_ID_TO_PROPERTY_STATE(1)
                  && system_property_cmd.property_id <= EP_ID_TO_PROPERTY_STATE(255)) {
                buf_len = sizeof(sli_cpc_system_cmd_t)
                          + sizeof(sli_cpc_property_id_t)
                          + sizeof(sli_cpc_endpoint_state_t)
                          + 2;
              } else if (system_property_cmd.property_id >= EP_ID_TO_PROPERTY_ENCRYPTION(1)
                         && system_property_cmd.property_id <= EP_ID_TO_PROPERTY_ENCRYPTION(255)) {
                buf_len = sizeof(sli_cpc_system_cmd_t)
                          + sizeof(sli_cpc_property_id_t)
                          + sizeof(bool)
                          + 2;
              }

              FATAL_ON(buf_len < 2);

              if (type == SLI_CPC_HDLC_FRAME_TYPE_UNNUMBERED) {
                is_unnumbered = true;
              } else {
                is_unnumbered = false;
              }

              if (!is_unnumbered) {
                TRACE_DRIVER("Sending ack %d on system endpoint", ack);
                cpc_unity_test_push_ack_in_driver(0, ack);
              }

              // Allocate for the tx command with two bytes for the CRC
              buffer = zalloc(buf_len);
              FATAL_ON(buffer == NULL);

              if (system_cmd.command_id == CMD_SYSTEM_PROP_VALUE_GET) {
                uint8_t ep_id = PROPERTY_ID_TO_EP_ID(system_property_cmd.property_id);

                // Create the get property reply
                TRACE_DRIVER("Replying to property get for ep #%d", ep_id);

                sli_cpc_drv_emul_create_get_endpoint_property((sli_cpc_system_cmd_t *)buffer,
                                                              system_property_cmd.property_id,
                                                              system_cmd.command_seq);
              } else if (system_cmd.command_id == CMD_SYSTEM_PROP_VALUE_SET) {
                TRACE_DRIVER("Replying to property set");
                uint8_t ep_id = PROPERTY_ID_TO_EP_ID(system_property_cmd.property_id);
                sli_cpc_endpoint_state_t requested_state;

                memcpy(&requested_state, property_payload, sizeof(requested_state));

                TRACE_DRIVER("Property set for ep #%d requested state %d, current %d",
                             ep_id, requested_state, ep_states[ep_id]);

                if (requested_state == SLI_CPC_STATE_CONNECTED) {
                  if (ep_states[ep_id] == SLI_CPC_STATE_OPEN) {
                    ep_states[ep_id] = SLI_CPC_STATE_CONNECTED;
                    TRACE_DRIVER("Property set forcing state CONNECTED for ep #%d",
                                 ep_id);
                  }
                } else if (requested_state == SLI_CPC_STATE_CLOSED) {
                  ep_states[ep_id] = SLI_CPC_STATE_CLOSED;
                }

                // Create the set property reply
                sli_cpc_drv_emul_create_set_endpoint_status_reply((sli_cpc_system_cmd_t *)buffer,
                                                                  PROPERTY_ID_TO_EP_ID(system_property_cmd.property_id),
                                                                  system_cmd.command_seq,
                                                                  ep_states[PROPERTY_ID_TO_EP_ID(system_property_cmd.property_id)]);
                if (requested_state == SLI_CPC_STATE_CLOSED && ep_states[ep_id] == SLI_CPC_STATE_CLOSED) {
                  ep_states[ep_id] = SLI_CPC_STATE_OPEN;
                  TRACE_DRIVER("Property set forcing state OPEN for ep #%d",
                               ep_id);
                }
              } else {
                BUG("Invalid command id");
              }

              // Compute payload CRC
              uint16_t fcs = sli_cpc_get_crc_sw(buffer, (uint16_t)(buf_len - 2));
              buffer[buf_len - 2] = (uint8_t)fcs;
              buffer[buf_len - 1] = (uint8_t)(fcs >> 8);

              ack = (uint8_t)(ack + 1);
              cpc_unity_test_push_pkt_in_driver(0, buffer, (uint16_t)buf_len, &seq, ack++, false, true);

              free(buffer);
            } else if (system_property_cmd.property_id == PROP_ENDPOINT_STATES) {
              TRACE_DRIVER("Sending ack %d on system endpoint", ack);
              cpc_unity_test_push_ack_in_driver(0, ack);
            }
            break;
          default:
            break;
        }
      } else {
        if (ret == SLI_CPC_HDLC_HEADER_RAW_SIZE) {
          sli_cpc_drv_emul_pkt_txed_notif(frame->header, frame->payload, 0, 0);
        } else {
          uint16_t fcs = hdlc_get_fcs(frame->payload, (uint16_t)(((size_t)ret - SLI_CPC_HDLC_HEADER_RAW_SIZE) - 2));
          sli_cpc_drv_emul_pkt_txed_notif(frame->header, frame->payload, (uint16_t)(((size_t)ret - SLI_CPC_HDLC_HEADER_RAW_SIZE) - 2), fcs);
        }
      }
    }
  }
  return 0;
}
