/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Emulation driver
 * @version 3.2.0
 *******************************************************************************
 * # License
 * <b>Copyright 2021 Silicon Laboratories Inc. www.silabs.com</b>
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

#include "server_core/core/crc.h"
#include "misc/logging.h"
#include "misc/utils.h"
#include "driver/driver_emul.h"
#include "server_core/core/hdlc.h"
#include "server_core/core/core.h"
#include "misc/sl_slist.h"
#include "misc/sl_status.h"
#include "test/unity/cpc_unity_common.h"
#include "server_core/system_endpoint/system.h"

static int fd_socket_drv;
static pthread_t drv_thread;
static sl_slist_node_t *sli_rx_pending_list_head;
static cpc_endpoint_state_t ep_states[255];

typedef struct {
  sl_slist_node_t node;
  frame_t *buf_handle;
  uint16_t payload_len;
} sli_buf_entry_rx;

static void* driver_thread_func(void* param);

pthread_t driver_emul_init(int* fd_core)
{
  int fd_sockets[2];
  uint32_t i;

  sl_slist_init(&sli_rx_pending_list_head);

  if (0 != socketpair(AF_UNIX, SOCK_DGRAM, 0, fd_sockets)) {
    FATAL("Create driver socket pair : %m");
  }

  fd_socket_drv  = fd_sockets[0];

  /* create driver thread */
  if (pthread_create(&drv_thread, NULL, driver_thread_func, NULL)) {
    FATAL("Error creating driver thread");
  }

  for (i = 0; i < 256; i++) {
    ep_states[i] = SL_CPC_STATE_OPEN;
  }

  *fd_core = fd_sockets[1];

  return drv_thread;
}

// -----------------------------------------------------------------------------
// Validation interface

void sli_cpc_drv_emul_set_ep_state(uint8_t id, cpc_endpoint_state_t state)
{
  FATAL_ON(id == 0);
  ep_states[id] = state;
}

void sli_cpc_drv_emul_submit_pkt_for_rx(void *header_buf, void *payload_buf, uint16_t payload_buf_len)
{
  uint8_t *buffer;

  buffer = (uint8_t*)malloc(sizeof(uint8_t) * (payload_buf_len + SLI_CPC_HDLC_HEADER_RAW_SIZE));
  FATAL_ON(buffer == NULL);

  if (buffer == NULL) {
    return;
  }

  memcpy(buffer, header_buf, SLI_CPC_HDLC_HEADER_RAW_SIZE);
  memcpy(&buffer[SLI_CPC_HDLC_HEADER_RAW_SIZE], payload_buf, payload_buf_len);

  (void)send(fd_socket_drv, buffer, payload_buf_len + SLI_CPC_HDLC_HEADER_RAW_SIZE, 0);

  free(buffer);
}

static void sli_cpc_drv_emul_create_get_endpoint_status_reply(sl_cpc_system_cmd_t *tx_command, uint8_t ep_id, uint8_t command_seq, cpc_endpoint_state_t state)
{
  FATAL_ON(tx_command == NULL);

  sl_cpc_system_property_cmd_t *reply_prop_cmd_buff;
  cpc_endpoint_state_t *reply_ep_state;

  // Reply to a PROPERTY-GET with a PROPERTY-IS
  tx_command->command_id = CMD_SYSTEM_PROP_VALUE_IS;
  tx_command->command_seq = command_seq;

  reply_prop_cmd_buff = (sl_cpc_system_property_cmd_t*) tx_command->payload;
  reply_ep_state = (cpc_endpoint_state_t*) reply_prop_cmd_buff->payload;

  reply_prop_cmd_buff->property_id = EP_ID_TO_PROPERTY_ID(ep_id);

  *reply_ep_state = state;

  tx_command->length = sizeof(sl_cpc_property_id_t) + sizeof(cpc_endpoint_state_t);
}

static void sli_cpc_drv_emul_create_set_endpoint_status_reply(sl_cpc_system_cmd_t *tx_command, uint8_t ep_id, uint8_t command_seq, cpc_endpoint_state_t state)
{
  FATAL_ON(tx_command == NULL);

  sl_cpc_system_property_cmd_t *reply_prop_cmd_buff;
  cpc_endpoint_state_t *reply_ep_state;

  // Reply to a PROPERTY-GET with a PROPERTY-IS
  tx_command->command_id = CMD_SYSTEM_PROP_VALUE_IS;
  tx_command->command_seq = command_seq;

  reply_prop_cmd_buff = (sl_cpc_system_property_cmd_t*) tx_command->payload;
  reply_ep_state = (cpc_endpoint_state_t*) reply_prop_cmd_buff->payload;

  reply_prop_cmd_buff->property_id = EP_ID_TO_PROPERTY_ID(ep_id);

  *reply_ep_state = state;

  tx_command->length = sizeof(sl_cpc_property_id_t) + sizeof(cpc_endpoint_state_t);
}

static void* driver_thread_func(void* param)
{
  (void)param;

  fd_set rfds;
  int retval;
  ssize_t ret;
  uint8_t temp_buffer[2048];
  frame_t *frame;
  int max_fd = 0;
  uint8_t control;
  uint8_t seq;
  uint8_t ack;
  uint8_t address;
  uint8_t  type;

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
      frame = (frame_t *)temp_buffer;
      control = hdlc_get_control(frame->header);
      address = hdlc_get_address(frame->header);
      type    = hdlc_get_frame_type(control);
      seq = hdlc_get_seq(control);
      ack = hdlc_get_ack(control);
      sl_cpc_system_cmd_t *rx_command = (sl_cpc_system_cmd_t *)frame->payload;
      sl_cpc_system_property_cmd_t *rx_property_cmd = (sl_cpc_system_property_cmd_t*)(rx_command->payload);

      if (address == 0) {
        switch (rx_command->command_id) {
          case CMD_SYSTEM_PROP_VALUE_GET:
          case CMD_SYSTEM_PROP_VALUE_SET:

            if (rx_property_cmd->property_id >= EP_ID_TO_PROPERTY_ID(1) && rx_property_cmd->property_id <= EP_ID_TO_PROPERTY_ID(255)) {
              uint8_t *buffer;
              size_t buf_len = sizeof(sl_cpc_system_cmd_t) + sizeof(sl_cpc_property_id_t) + sizeof(cpc_endpoint_state_t) + 2;
              FATAL_ON(buf_len < 2);
              bool is_unnumbered;

              if (type == SLI_CPC_HDLC_FRAME_TYPE_UNNUMBERED) {
                is_unnumbered = true;
              } else {
                is_unnumbered = false;
              }

              if (!is_unnumbered) {
                cpc_unity_test_push_ack_in_driver(0, ack);
              }

              // Allocate for the tx command with two bytes for the CRC
              buffer = malloc(buf_len);
              FATAL_ON(buffer == NULL);

              if (rx_command->command_id == CMD_SYSTEM_PROP_VALUE_GET) {
                // Create the get property reply
                sli_cpc_drv_emul_create_get_endpoint_status_reply((sl_cpc_system_cmd_t *)buffer,
                                                                  PROPERTY_ID_TO_EP_ID(rx_property_cmd->property_id),
                                                                  rx_command->command_seq,
                                                                  ep_states[PROPERTY_ID_TO_EP_ID(rx_property_cmd->property_id)]);
              } else if (rx_command->command_id == CMD_SYSTEM_PROP_VALUE_SET) {
                // Create the set property reply
                sli_cpc_drv_emul_create_set_endpoint_status_reply((sl_cpc_system_cmd_t *)buffer,
                                                                  PROPERTY_ID_TO_EP_ID(rx_property_cmd->property_id),
                                                                  rx_command->command_seq,
                                                                  ep_states[PROPERTY_ID_TO_EP_ID(rx_property_cmd->property_id)]);
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
            } else if (rx_property_cmd->property_id == PROP_ENDPOINT_STATES) {
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
