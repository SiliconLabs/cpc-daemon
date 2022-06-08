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

#include "server_core/system_endpoint/system_callbacks.h"
#include "server_core/core/core.h"
#include "server_core/server/server.h"
#include "misc/logging.h"
#include "lib/sl_cpc.h"
#include "server_core/cpcd_exchange.h"

static int fd_ctrl_data_of_pending_open = 0;

void sl_cpc_system_set_pending_connection(int fd)
{
  fd_ctrl_data_of_pending_open = fd;
}

void reply_to_closing_endpoint_on_secondary_callback(sl_cpc_system_command_handle_t *handle,
                                                     sl_cpc_property_id_t property_id,
                                                     void* property_value,
                                                     size_t property_length,
                                                     sl_status_t status)
{
  (void)handle;
  (void)property_length;
  (void)property_value;

  uint8_t ep_id = PROPERTY_ID_TO_EP_ID(property_id);

  switch (status) {
    case SL_STATUS_IN_PROGRESS:
    case SL_STATUS_OK:
      TRACE_SYSTEM("Secondary closed the endpoint #%d, acknowledged it", ep_id);
      break;

    case SL_STATUS_TIMEOUT:
    case SL_STATUS_ABORT:
    default:
      WARN("Secondary closed the endpoint #%d, could not acknowledge it", ep_id);
      break;
  }
}

void property_get_single_endpoint_state_and_reply_to_pending_open_callback(sl_cpc_system_command_handle_t *handle,
                                                                           sl_cpc_property_id_t property_id,
                                                                           void* property_value,
                                                                           size_t property_length,
                                                                           sl_status_t status)
{
  (void) handle;
  bool can_open = false;
  bool secondary_reachable = false;
  cpcd_exchange_buffer_t *interface_buffer;
  const size_t buffer_len = sizeof(cpcd_exchange_buffer_t) + sizeof(bool);
  uint8_t buffer[buffer_len];
  uint8_t endpoint_id;
  cpc_endpoint_state_t remote_endpoint_state;

  switch (status) {
    case SL_STATUS_OK:
      TRACE_SERVER("Property-get::PROP_ENDPOINT_STATE Successful callback");
      remote_endpoint_state = *(uint8_t *)property_value;
      secondary_reachable = true;
      break;
    case SL_STATUS_IN_PROGRESS:
      TRACE_SERVER("Property-get::PROP_ENDPOINT_STATE Successful callback after retry(ies)");
      remote_endpoint_state = *(uint8_t *)property_value;
      secondary_reachable = true;
      break;
    case SL_STATUS_TIMEOUT:
      WARN("Property-get::PROP_ENDPOINT_STATE timed out");
      break;
    case SL_STATUS_ABORT:
      WARN("Property-get::PROP_ENDPOINT_STATE aborted");
      break;
    default:
      FATAL();
  }

  interface_buffer = (cpcd_exchange_buffer_t*)buffer;

  /* Sanity checks */
  {
    /* This callback should be called only when we need to reply to a client pending on an open_endpoint call */
    BUG_ON(fd_ctrl_data_of_pending_open == 0);

    /* This function's signature is for all properties get/set. Make sure we
     * are dealing with PROP_ENDPOINT_STATE and with the correct property_length*/
    BUG_ON(property_id < PROP_ENDPOINT_STATE_1 || property_id > PROP_ENDPOINT_STATE_255);

    if (secondary_reachable) {
      BUG_ON(property_length != 1);
    }
  }

  endpoint_id = PROPERTY_ID_TO_EP_ID(property_id);

  interface_buffer->endpoint_number = endpoint_id;

  if (secondary_reachable && (remote_endpoint_state == SL_CPC_STATE_OPEN)
      && (core_get_endpoint_state(endpoint_id) == SL_CPC_STATE_CLOSED || core_get_endpoint_state(endpoint_id) == SL_CPC_STATE_OPEN)) {
    can_open = true;
    server_open_endpoint(endpoint_id);
  }

  memcpy(interface_buffer->payload, &can_open, sizeof(bool));

  if (!can_open && secondary_reachable) {
    TRACE_SERVER("Cannot open endpoint #%d. Current state on the secondary is: %d. Current state on daemon is: %d", endpoint_id, remote_endpoint_state, core_get_endpoint_state(endpoint_id));
  }

  if (!secondary_reachable) {
    WARN("Could not read endpoint state on the secondary");
  }

  /* Acknowledge this request */
  {
    interface_buffer->type = EXCHANGE_OPEN_ENDPOINT_QUERY;
    ssize_t ret = send(fd_ctrl_data_of_pending_open, interface_buffer, buffer_len, 0);
    TRACE_SERVER("Replied to endpoint open query on ep#%d", endpoint_id);

    if (ret == -1) {
      WARN("Failed to acknowledge the open request for endpoint #%d. %m", endpoint_id);
    } else if ((size_t)ret != buffer_len) {
      BUG("Failed to acknowledge the open request for endpoint #%d. Sent %d, Expected %d", endpoint_id, (int)ret, (int)buffer_len);
    }
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
    case SL_STATUS_ABORT:
      WARN("The noop keep alive was aborted");
      TRACE_SERVER("NOOP failed!");
      break;
    default:
      FATAL();
      break;
  }
}
