/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - System endpoint callback
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

#include <string.h>
#include <sys/socket.h>

#include "system_callbacks.h"
#include "log.h"
#include "core.h"
#include "sl_cpc.h"
#include "server_internal.h"
#include "cpc_interface.h"

static int fd_ctrl_data_of_pending_open = 0;

void sl_cpc_system_set_pending_connection(int fd)
{
  fd_ctrl_data_of_pending_open = fd;
}

void property_get_single_endpoint_state_and_reply_to_pending_open_callback(sl_cpc_system_command_handle_t *handle,
                                                                           sl_cpc_property_id_t property_id,
                                                                           void* property_value,
                                                                           size_t property_length,
                                                                           sl_status_t status)
{
  (void) handle;
  bool can_open = false;
  cpc_interface_buffer_t *interface_buffer;
  const size_t buffer_len = sizeof(cpc_interface_buffer_t) + sizeof(bool);
  uint8_t buffer[buffer_len];
  uint8_t endpoint_id;
  cpc_endpoint_state_t remote_endpoint_state;

  switch (status) {
    case SL_STATUS_OK:
      TRACE_SERVER("Property-get::PROP_ENDPOINT_STATE Successful callback");
      break;
    case SL_STATUS_IN_PROGRESS:
      TRACE_SERVER("Property-get::PROP_ENDPOINT_STATE Successful callback after retry(ies)");
      break;
    case SL_STATUS_TIMEOUT:
      TRACE_SERVER("Property-get::PROP_ENDPOINT_STATE timed out");
      FATAL();
      break;
    case SL_STATUS_FAIL:
      TRACE_SERVER("Property-get::PROP_ENDPOINT_STATE fail ");
      FATAL();
      break;
    default:
      FATAL();
  }

  interface_buffer = (cpc_interface_buffer_t*)buffer;

  /* Sanity checks */
  {
    /* This callback should be called only when we need to reply to a client pending on an open_endpoint call */
    BUG_ON(fd_ctrl_data_of_pending_open == 0);

    /* This function's signature is for all properties get/set. Make sure we
     * are dealing with PROP_ENDPOINT_STATE and with the correct property_length*/
    BUG_ON(property_id < PROP_ENDPOINT_STATE_1 || property_id > PROP_ENDPOINT_STATE_255);
    BUG_ON(property_length != 1);
  }

  endpoint_id = PROPERTY_ID_TO_EP_ID(property_id);

  remote_endpoint_state = *(uint8_t *)property_value;

  interface_buffer->endpoint_number = endpoint_id;

  if (((remote_endpoint_state) == SL_CPC_STATE_OPEN)
      && (core_get_endpoint_state(endpoint_id) == SL_CPC_STATE_CLOSED || core_get_endpoint_state(endpoint_id) == SL_CPC_STATE_OPEN)) {
    can_open = true;
    server_open_endpoint(PROPERTY_ID_TO_EP_ID(property_id));
  }

  memcpy(interface_buffer->payload, &can_open, sizeof(bool));

  /* Acknowledge this request */
  {
    interface_buffer->type = EXCHANGE_OPEN_ENDPOINT_QUERY;
    ssize_t ret = send(fd_ctrl_data_of_pending_open, interface_buffer, buffer_len, 0);
    FATAL_SYSCALL_ON(ret < 0);
    FATAL_ON((size_t)ret != buffer_len);
  }
}

void system_noop_cmd_callback_t(sl_cpc_system_command_handle_t *handle,
                                sl_status_t status)
{
  (void) handle;

  switch (status) {
    case SL_STATUS_OK:
      TRACE_SERVER("NOOP success");
      break;
    case SL_STATUS_IN_PROGRESS:
      TRACE_SERVER("NOOP success with a least one retry");
      break;
    case SL_STATUS_TIMEOUT:
      WARN("The noop keep alive timed out, link dead");
      TRACE_SERVER("NOOP timed out!");
      break;
    case SL_STATUS_FAIL:
      WARN("The noop keep alive failed, link dead");
      TRACE_SERVER("NOOP failed!");
      break;
    default:
      FATAL();
      break;
  }
}
