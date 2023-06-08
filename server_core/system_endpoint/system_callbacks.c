/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - System endpoint callback
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

#include <string.h>
#include <sys/socket.h>

#include "cpcd/config.h"
#include "cpcd/exchange.h"
#include "cpcd/logging.h"

#include "server_core/system_endpoint/system_callbacks.h"
#include "server_core/core/core.h"
#include "server_core/server/server.h"
#include "lib/sl_cpc.h"

static int fd_ctrl_data_of_pending_open = 0;

#if defined(ENABLE_ENCRYPTION)
static uint8_t ep_id_encryption_queried = 0;
#endif

sl_cpc_system_open_step_t system_open_ep_step = SL_CPC_SYSTEM_OPEN_STEP_IDLE;

bool sl_cpc_system_is_waiting_for_status_reply(void)
{
  return fd_ctrl_data_of_pending_open != 0;
}

void sl_cpc_system_set_pending_connection(int fd)
{
  fd_ctrl_data_of_pending_open = fd;
}

void reply_to_closing_endpoint_on_secondary_async_callback(sl_cpc_system_command_handle_t *handle,
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
      TRACE_SERVER("Acknowledged secondary of asynchronously closing ep#%d", ep_id);
      break;

    case SL_STATUS_TIMEOUT:
    case SL_STATUS_ABORT:
    default:
      WARN("Secondary did not receive acknowledge of asynchronously closing ep#%d", ep_id);
      break;
  }
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
      TRACE_SERVER("Acknowledged secondary of closing ep#%d", ep_id);
      core_set_endpoint_state(ep_id, SL_CPC_STATE_CLOSED);
      break;

    case SL_STATUS_TIMEOUT:
    case SL_STATUS_ABORT:
    default:
      WARN("Secondary did not receive acknowledge of closing ep#%d", ep_id);
      break;
  }
}

/***************************************************************************//**
 * Send an acknowledge to the ctrl socket about the open endpoint query.
 ******************************************************************************/
static void system_send_open_endpoint_ack(uint8_t endpoint_id, bool can_open)
{
  const size_t buffer_len = sizeof(cpcd_exchange_buffer_t) + sizeof(uint8_t) + sizeof(bool);
  cpcd_exchange_buffer_t *interface_buffer;
  uint8_t buffer[buffer_len];

  interface_buffer = (cpcd_exchange_buffer_t*)buffer;

  // populate fields related to the query
  interface_buffer->type = EXCHANGE_OPEN_ENDPOINT_QUERY;
  interface_buffer->endpoint_number = endpoint_id;
  memset(interface_buffer->payload, 0, 1);
  memcpy(&(interface_buffer->payload[1]), &can_open, sizeof(bool));

  ssize_t ret = send(fd_ctrl_data_of_pending_open, interface_buffer, buffer_len, 0);
  TRACE_SERVER("Replied to endpoint open query on ep#%d", endpoint_id);

  if (ret == -1) {
    WARN("Failed to acknowledge the open request for endpoint #%d. %m", endpoint_id);
  } else if ((size_t)ret != buffer_len) {
    BUG("Failed to acknowledge the open request for endpoint #%d. Sent %d, Expected %d",
        endpoint_id, (int)ret, (int)buffer_len);
  }

  system_open_ep_step = SL_CPC_SYSTEM_OPEN_STEP_DONE;
}

/***************************************************************************//**
 * Common routine to finalize a request to open an endpoint, successful or not.
 * If the endpoint was successfully opened, the server will be notified to
 * create the endpoint socket, and a response will be sent to client on the
 * control socket.
 ******************************************************************************/
static void system_finalize_open_endpoint(uint8_t endpoint_id, bool encryption, bool can_open)
{
  if (can_open) {
    server_set_endpoint_encryption(endpoint_id, encryption);
    server_open_endpoint(endpoint_id);
  }

  system_send_open_endpoint_ack(endpoint_id, can_open);
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
  uint8_t endpoint_id;
  cpc_endpoint_state_t remote_endpoint_state;

  switch (status) {
    case SL_STATUS_OK:
      BUG_ON(property_length != sizeof(cpc_endpoint_state_t));
      TRACE_SERVER("Property-get::PROP_ENDPOINT_STATE Successful callback");
      remote_endpoint_state = core_state_mapper(*(uint8_t*)property_value);
      secondary_reachable = true;
      break;
    case SL_STATUS_IN_PROGRESS:
      BUG_ON(property_length != sizeof(cpc_endpoint_state_t));
      TRACE_SERVER("Property-get::PROP_ENDPOINT_STATE Successful callback after retry(ies)");
      remote_endpoint_state = core_state_mapper(*(uint8_t*)property_value);
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

  if (secondary_reachable && (remote_endpoint_state == SL_CPC_STATE_OPEN)
      && (core_get_endpoint_state(endpoint_id) == SL_CPC_STATE_CLOSED || core_get_endpoint_state(endpoint_id) == SL_CPC_STATE_OPEN)) {
    can_open = true;

    // endpoint is ready to be opened, the encryption status must now be fetched
  }

  if (!can_open && secondary_reachable) {
    TRACE_SERVER("Cannot open endpoint #%d. Current state on the secondary is: %s. Current state on daemon is: %s", endpoint_id, core_stringify_state(remote_endpoint_state), core_stringify_state(core_get_endpoint_state(endpoint_id)));
  }

  if (!secondary_reachable) {
    WARN("Could not read endpoint state on the secondary");
  }

  if (!can_open) {
    // Send "failed to open" ack to control socket
    system_finalize_open_endpoint(endpoint_id, false, can_open);
  } else {
    if (config.use_encryption) {
#if defined(ENABLE_ENCRYPTION)
      // As the secondary might not implement the encryption per-endpoint
      // and reply with a "not implemented" message (that doesn't contain
      // the endpoint ID), it must be stored to be accessed later
      ep_id_encryption_queried = endpoint_id;

      system_open_ep_step = SL_CPC_SYSTEM_OPEN_STEP_STATE_FETCHED;
#else
      // Don't bother asking for encryption state, acknowledge
      // endpoint opening to the control socket
      system_finalize_open_endpoint(endpoint_id, false, can_open);
#endif
    } else {
      // Don't bother asking for encryption state, acknowledge
      // endpoint opening to the control socket
      system_finalize_open_endpoint(endpoint_id, false, can_open);
    }
  }
}

#if defined(ENABLE_ENCRYPTION)
void property_get_single_endpoint_encryption_state_and_reply_to_pending_open_callback(sl_cpc_system_command_handle_t *handle,
                                                                                      sl_cpc_property_id_t property_id,
                                                                                      void* property_value,
                                                                                      size_t property_length,
                                                                                      sl_status_t status)
{
  (void) handle;
  (void) property_length;
  uint8_t endpoint_id = 0;
  bool encryption;
  bool secondary_reachable = false;

  switch (status) {
    case SL_STATUS_OK:
      TRACE_SERVER("Property-get::PROP_ENDPOINT_ENCRYPTION Successful callback");
      secondary_reachable = true;
      break;
    case SL_STATUS_IN_PROGRESS:
      TRACE_SERVER("Property-get::PROP_ENDPOINT_ENCRYPTION Successful callback after retry(ies)");
      secondary_reachable = true;
      break;
    case SL_STATUS_TIMEOUT:
      WARN("Property-get::PROP_ENDPOINT_ENCRYPTION timed out");
      break;
    case SL_STATUS_ABORT:
      WARN("Property-get::PROP_ENDPOINT_ENCRYPTION aborted");
      break;
    default:
      FATAL();
  }

  /* This callback should be called only when we need to reply to a client pending on an open_endpoint call */
  BUG_ON(fd_ctrl_data_of_pending_open == 0);

  if (secondary_reachable) {
    if (property_id >= EP_ID_TO_PROPERTY_ENCRYPTION(0) && property_id <= EP_ID_TO_PROPERTY_ENCRYPTION(255)) {
      endpoint_id = PROPERTY_ID_TO_EP_ID(property_id);
      FATAL_ON(ep_id_encryption_queried != endpoint_id);

      encryption = *((bool*)property_value);
      TRACE_SERVER("Secondary has per-endpoint encryption: ep#%d: encryption=%d",
                   endpoint_id, encryption);
    } else if (property_id == PROP_LAST_STATUS) {
      sl_cpc_system_status_t status;

      status = *((sl_cpc_system_status_t*)property_value);
      FATAL_ON(status != STATUS_PROP_NOT_FOUND);

      encryption = true;
      endpoint_id = ep_id_encryption_queried;
      TRACE_SERVER("Secondary doesn't have per-endpoint encryption, forcing encryption of ep#%d", endpoint_id);
    } else {
      WARN("Unexpected property reply when fetching encryption state of ep#%d", ep_id_encryption_queried);
      system_finalize_open_endpoint(endpoint_id, false, false);
      return;
    }

    system_finalize_open_endpoint(endpoint_id, encryption, true);
  } else {
    WARN("Could not read endpoint encryption state for ep#%d on the secondary", ep_id_encryption_queried);
    system_finalize_open_endpoint(endpoint_id, false, false);
  }
}
#endif

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
