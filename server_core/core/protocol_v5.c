/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Protocol V5 Implementation
 *******************************************************************************
 * # License
 * <b>Copyright 2023 Silicon Laboratories Inc. www.silabs.com</b>
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

#include "config.h"

#include <errno.h>

#include "cpcd/endianness.h"
#include "cpcd/logging.h"

#include "cpcd/sl_status.h"
#include "server_core/system_endpoint/system.h"

#include "protocol.h"
#include "protocol_internal.h"

/*
 * Enum with all endpoint states supported by this protocol.
 */
SL_ENUM(sli_cpc_endpoint_state_v5_t) {
  PROTOCOL_V5_STATE_FREED = 0,
  PROTOCOL_V5_STATE_OPEN,
  PROTOCOL_V5_STATE_CLOSED,
  PROTOCOL_V5_STATE_CLOSING,
  PROTOCOL_V5_STATE_CONNECTING,
  PROTOCOL_V5_STATE_CONNECTED,
  PROTOCOL_V5_STATE_SHUTTING_DOWN,
  PROTOCOL_V5_STATE_SHUTDOWN,
  PROTOCOL_V5_STATE_REMOTE_SHUTDOWN,
  PROTOCOL_V5_STATE_DISCONNECTED,
  PROTOCOL_V5_STATE_ERROR_DESTINATION_UNREACHABLE,
  PROTOCOL_V5_STATE_ERROR_SECURITY_INCIDENT,
  PROTOCOL_V5_STATE_ERROR_FAULT,
};

/***************************************************************************//**
 * Convert an endpoint state to string.
 ******************************************************************************/
static const char* protocol_state_to_str(sli_cpc_endpoint_state_v5_t state)
{
  switch (state) {
    case PROTOCOL_V5_STATE_FREED:
      return "FREED";
    case PROTOCOL_V5_STATE_OPEN:
      return "OPEN";
    case PROTOCOL_V5_STATE_CLOSED:
      return "CLOSED";
    case PROTOCOL_V5_STATE_CLOSING:
      return "CLOSING";
    case PROTOCOL_V5_STATE_CONNECTING:
      return "CONNECTING";
    case PROTOCOL_V5_STATE_CONNECTED:
      return "CONNECTED";
    case PROTOCOL_V5_STATE_SHUTTING_DOWN:
      return "SHUTTING_DOWN";
    case PROTOCOL_V5_STATE_SHUTDOWN:
      return "SHUTDOWN";
    case PROTOCOL_V5_STATE_REMOTE_SHUTDOWN:
      return "REMOTE_SHUTDOWN";
    case PROTOCOL_V5_STATE_DISCONNECTED:
      return "DISCONNECTED";
    case PROTOCOL_V5_STATE_ERROR_DESTINATION_UNREACHABLE:
      return "ERROR_DESTINATION_UNREACHABLE";
    case PROTOCOL_V5_STATE_ERROR_SECURITY_INCIDENT:
      return "ERROR_SECURITY_INCIDENT";
    case PROTOCOL_V5_STATE_ERROR_FAULT:
      return "ERROR_FAULT";
    default:
      return "UNKNOWN";
  }
}

/***************************************************************************//**
 * Callback called when the endpoint state is received.
 ******************************************************************************/
static void is_endpoint_opened_reply_v5(sli_cpc_property_id_t property_id,
                                        void *property_value,
                                        size_t property_length,
                                        void *user_data,
                                        sl_status_t status)
{
  struct protocol_callback_context *ctx = (struct protocol_callback_context*)user_data;
  sli_cpc_endpoint_state_v5_t remote_endpoint_state;
  on_is_opened_completion_t callback;
  bool secondary_reachable = false;
  uint8_t endpoint_id;

  FATAL_ON(ctx == NULL);
  callback = (on_is_opened_completion_t)ctx->callback;

  endpoint_id = PROPERTY_ID_TO_EP_ID(property_id);

  // Sanity checks
  {
    // This function's signature is for all properties get/set. Make sure we
    // are dealing with PROP_ENDPOINT_STATE and with the correct property_length
    BUG_ON(property_id < PROP_ENDPOINT_STATE_1 || property_id > PROP_ENDPOINT_STATE_255);

    BUG_ON(endpoint_id != ctx->ep->id);
  }

  switch (status) {
    case SL_STATUS_OK:
    case SL_STATUS_IN_PROGRESS:
      TRACE_CORE("Property-get::PROP_ENDPOINT_STATE Successful callback");

      if (property_length != sizeof(remote_endpoint_state)) {
        // If payload size is invalid, let secondary_reachable to false
        // and exit the switch case, nothing more we can do
        break;
      }

      remote_endpoint_state = *((uint8_t*)property_value);
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

  if (secondary_reachable) {
    if (remote_endpoint_state == PROTOCOL_V5_STATE_OPEN
        || remote_endpoint_state == PROTOCOL_V5_STATE_CONNECTING
        || remote_endpoint_state == PROTOCOL_V5_STATE_CONNECTED) {
      status = SL_STATUS_OK;
    } else {
      // secondary replied but is not opened
      TRACE_CORE("Cannot open endpoint #%d. Current state on the secondary is: %s.",
                 endpoint_id,
                 protocol_state_to_str(remote_endpoint_state));
      status = SL_STATUS_NOT_AVAILABLE;
    }
  } else {
    WARN("Could not read endpoint state on the secondary");
    status = SL_STATUS_INVALID_TYPE;
  }

  callback(ctx->ep, status, ctx->callback_data);

  protocol_free_callback_context(ctx);
}

/***************************************************************************//**
 * Callback called when a response to a `connect` is received.
 ******************************************************************************/
static void on_connect_reply_v5(sli_cpc_property_id_t property_id,
                                void *property_value,
                                size_t property_length,
                                void *user_data,
                                sl_status_t status)
{
  struct protocol_callback_context *ctx = (struct protocol_callback_context*)user_data;
  sli_cpc_endpoint_state_v5_t *remote_state = NULL;
  uint8_t ep_id = PROPERTY_ID_TO_EP_ID(property_id);
  on_connect_completion_t callback;

  FATAL_ON(ctx == NULL);

  callback = (on_connect_completion_t)ctx->callback;

  switch (status) {
    case SL_STATUS_IN_PROGRESS:
    case SL_STATUS_OK:
      if (property_length != sizeof(sli_cpc_endpoint_state_v5_t)) {
        TRACE_CORE("Connection confirmation for ep#%d has invalid length (expected %zd, got %zd)",
                   (int)ep_id, sizeof(sli_cpc_endpoint_state_v5_t), property_length);
        callback(ctx->ep, SL_STATUS_INVALID_TYPE);
        break;
      }

      // the secondary should only reply with CONNECTED or CLOSED
      // state to a connect request.
      remote_state = (sli_cpc_endpoint_state_v5_t*)property_value;
      if (*remote_state == PROTOCOL_V5_STATE_CONNECTED) {
        callback(ctx->ep, SL_STATUS_OK);
      } else if (*remote_state == PROTOCOL_V5_STATE_CLOSED) {
        callback(ctx->ep, SL_STATUS_NOT_READY);
      } else {
        WARN("remote replied with unexpected state, got %s",
             protocol_state_to_str(*remote_state));
        callback(ctx->ep, SL_STATUS_INVALID_PARAMETER);
      }

      break;

    case SL_STATUS_TIMEOUT:
    case SL_STATUS_ABORT:
      WARN("Failed to receive connection notification confirmation for ep#%d", ep_id);
      callback(ctx->ep, SL_STATUS_FAIL);
      break;
    default:
      FATAL("Unknown status %d on_connect_notification", status);
      break;
  }

  protocol_free_callback_context(ctx);
}

/***************************************************************************//**
 * Callback called when the response to a disconnect is received.
 ******************************************************************************/
static void on_disconnect_reply_v5(sli_cpc_property_id_t property_id,
                                   void *property_value,
                                   size_t property_length,
                                   void *user_arg,
                                   sl_status_t status)
{
  struct protocol_callback_context *ctx = (struct protocol_callback_context*)user_arg;
  sli_cpc_endpoint_state_v5_t *remote_state = NULL;
  uint8_t ep_id = PROPERTY_ID_TO_EP_ID(property_id);
  on_disconnect_completion_t callback;

  FATAL_ON(ctx == NULL);

  callback = (on_disconnect_completion_t)ctx->callback;

  switch (status) {
    case SL_STATUS_IN_PROGRESS:
    case SL_STATUS_OK:
      TRACE_CORE("Disconnect reply received for ep#%d", ep_id);

      if (property_length != sizeof(sli_cpc_endpoint_state_v5_t)) {
        WARN("remote replied with invalid property length (%zu)", property_length);

        callback(ctx->ep, SL_STATUS_INVALID_TYPE);
        break;
      }

      remote_state = (sli_cpc_endpoint_state_v5_t*)property_value;

      if (*remote_state == PROTOCOL_V5_STATE_DISCONNECTED) {
        // Disconnection accepted by remote
        callback(ctx->ep, SL_STATUS_OK);
      } else if (*remote_state == PROTOCOL_V5_STATE_REMOTE_SHUTDOWN) {
        // Immediate disconnection refused by remote
        // as it still has pending frames to send.
        callback(ctx->ep, SL_STATUS_IN_PROGRESS);
      } else {
        WARN("remote replied with unexpected state, got %s",
             protocol_state_to_str(*remote_state));
        callback(ctx->ep, SL_STATUS_INVALID_PARAMETER);
      }

      break;

    case SL_STATUS_TIMEOUT:
    case SL_STATUS_ABORT:
      WARN("Failed to receive disconnection notification for ep#%d", ep_id);
      callback(ctx->ep, SL_STATUS_FAIL);
      break;
    default:
      FATAL("Unknown status %d during disconnection notification", status);
      break;
  }

  protocol_free_callback_context(ctx);
}

/***************************************************************************//**
 * Callback called when the response to a `terminate` is received.
 ******************************************************************************/
static void on_terminate_reply_v5(sli_cpc_property_id_t property_id,
                                  void *property_value,
                                  size_t property_length,
                                  void *user_arg,
                                  sl_status_t status)
{
  struct protocol_callback_context *ctx = (struct protocol_callback_context*)user_arg;
  sli_cpc_endpoint_state_v5_t *remote_state = NULL;
  uint8_t ep_id = PROPERTY_ID_TO_EP_ID(property_id);
  on_terminate_completion_t callback;

  FATAL_ON(ctx == NULL);

  callback = (on_terminate_completion_t)ctx->callback;

  switch (status) {
    case SL_STATUS_IN_PROGRESS:
    case SL_STATUS_OK:
      TRACE_CORE("Terminate reply received for ep#%d", ep_id);

      if (property_length == sizeof(sli_cpc_endpoint_state_v5_t)) {
        remote_state = (sli_cpc_endpoint_state_v5_t*)property_value;
        if (*remote_state != PROTOCOL_V5_STATE_CLOSED) {
          WARN("remote replied with unexpected state, got %s, expected %s",
               protocol_state_to_str(*remote_state),
               protocol_state_to_str(PROTOCOL_V5_STATE_CLOSED));
        }
      } else {
        WARN("remote replied with invalid property length (%zu)", property_length);
      }

      callback(ctx->ep, SL_STATUS_OK);
      break;

    case SL_STATUS_TIMEOUT:
    case SL_STATUS_ABORT:
      WARN("Failed to receive disconnection notification for ep#%d", ep_id);
      callback(ctx->ep, SL_STATUS_FAIL);
      break;
    default:
      FATAL("Unknown status %d during disconnection notification", status);
      break;
  }

  protocol_free_callback_context(ctx);
}

#if defined(ENABLE_ENCRYPTION)
/***************************************************************************//**
 * Callback called when the response to setting security counters is received.
 ******************************************************************************/
static void on_set_security_counters_reply_v5(sli_cpc_property_id_t property_id,
                                              void *property_value,
                                              size_t property_length,
                                              void *user_arg,
                                              sl_status_t status)
{
  struct protocol_callback_context *ctx = (struct protocol_callback_context*)user_arg;
  on_set_security_counters_completion_t callback;

  FATAL_ON(ctx == NULL);
  callback = (on_set_security_counters_completion_t)ctx->callback;

  switch (status) {
    case SL_STATUS_IN_PROGRESS:
    case SL_STATUS_OK:
      if (property_id == PROP_LAST_STATUS) {
        // case where the remote doesn't support updating the counters
        sl_cpc_system_status_t system_status;

        // first of all, check the length
        if (property_length != sizeof(sl_cpc_system_status_t)) {
          status = SL_STATUS_INVALID_TYPE;
        } else {
          system_status = (sl_cpc_system_status_t) u32_from_le((uint8_t*)property_value);

          // this is the only case we're really interested in, if the
          // remote doesn't support this command. In that case it should
          // be handled in a special manner. Every other situation is an
          // critical error.
          if (system_status == STATUS_PROP_NOT_FOUND) {
            status = SL_STATUS_NOT_SUPPORTED;
          } else {
            status = SL_STATUS_FAIL;
          }
        }
      } else if (property_id >= PROP_ENDPOINT_ENCRYPTION
                 && property_id <= PROP_ENDPOINT_ENCRYPTION + 255) {
        // case where remote supports the command
        uint8_t ep_id = PROPERTY_ID_TO_EP_ID(property_id);
        size_t expected_length;

        TRACE_CORE("Updated security counters for ep#%d", ep_id);
        expected_length = 2 * sizeof(uint32_t);

        if (property_length == expected_length) {
          status = SL_STATUS_OK;
        } else {
          status = SL_STATUS_INVALID_TYPE;
        }
      } else {
        status = SL_STATUS_FAIL;
      }

      break;

    case SL_STATUS_TIMEOUT:
    case SL_STATUS_ABORT:
      status = SL_STATUS_FAIL;
      break;
    default:
      break;
  }

  callback(ctx->ep, status, ctx->callback_data);

  protocol_free_callback_context(ctx);
}
#endif

/***************************************************************************//**
 * Convert bytestream to internal core state.
 ******************************************************************************/
sl_status_t parse_endpoint_state_v5(const uint8_t *payload,
                                    const size_t payload_len,
                                    sli_cpc_endpoint_state_t *state)
{
  sl_status_t ret;
  uint8_t byte;

  if (payload_len != 1) {
    // the payload is not the right size, nothing we can do
    return SL_STATUS_INVALID_TYPE;
  }

  byte = payload[0];

  switch (byte) {
    case PROTOCOL_V5_STATE_FREED:
    case PROTOCOL_V5_STATE_OPEN:
    case PROTOCOL_V5_STATE_CLOSED:
    case PROTOCOL_V5_STATE_CLOSING:
    case PROTOCOL_V5_STATE_CONNECTING:
    case PROTOCOL_V5_STATE_CONNECTED:
    case PROTOCOL_V5_STATE_SHUTTING_DOWN:
    case PROTOCOL_V5_STATE_SHUTDOWN:
    case PROTOCOL_V5_STATE_REMOTE_SHUTDOWN:
    case PROTOCOL_V5_STATE_DISCONNECTED:
    case PROTOCOL_V5_STATE_ERROR_DESTINATION_UNREACHABLE:
    case PROTOCOL_V5_STATE_ERROR_SECURITY_INCIDENT:
    case PROTOCOL_V5_STATE_ERROR_FAULT:
      ret = SL_STATUS_OK;
      *state = (sli_cpc_endpoint_state_t)byte;
      break;

    default:
      ret = SL_STATUS_INVALID_RANGE;
      break;
  }

  return ret;
}

/***************************************************************************//**
 * Issue command to get endpoint state
 ******************************************************************************/
void is_endpoint_opened_v5(sl_cpc_endpoint_t *ep,
                           on_is_opened_completion_t callback,
                           void *callback_ctx)
{
  struct protocol_callback_context *ctx;

  ctx = protocol_new_callback_context();
  FATAL_ON(ctx == NULL);

  ctx->ep = ep;
  ctx->callback = callback;
  ctx->callback_data = callback_ctx;

  TRACE_CORE("Fetching endpoint state for ep#%d", ep->id);
  sl_cpc_system_cmd_property_get(is_endpoint_opened_reply_v5,
                                 EP_ID_TO_PROPERTY_STATE(ep->id),
                                 ctx,
                                 5,
                                 100000,
                                 SYSTEM_EP_IFRAME);
}

/***************************************************************************//**
 * Issue command to connect to endpoint.
 ******************************************************************************/
void connect_endpoint_v5(sl_cpc_endpoint_t *ep,
                         on_connect_completion_t callback)
{
  sli_cpc_endpoint_state_v5_t connected_state = PROTOCOL_V5_STATE_CONNECTED;
  struct protocol_callback_context *ctx;

  ctx = protocol_new_callback_context();
  FATAL_ON(ctx == NULL);

  ctx->ep = ep;
  ctx->callback = callback;

  // Notify the secondary that client is connecting
  sl_cpc_system_cmd_property_set(on_connect_reply_v5,
                                 EP_ID_TO_PROPERTY_STATE(ep->id),
                                 &connected_state,
                                 sizeof(connected_state),
                                 ctx,
                                 0, // unlimited retries
                                 100000, // 100ms between retries
                                 SYSTEM_EP_IFRAME);
}

/***************************************************************************//**
 * Issue command to disconnect to endpoint.
 ******************************************************************************/
void disconnect_endpoint_v5(sl_cpc_endpoint_t *ep,
                            on_disconnect_completion_t callback)
{
  sli_cpc_endpoint_state_v5_t disconnected_state = PROTOCOL_V5_STATE_DISCONNECTED;
  struct protocol_callback_context *ctx;

  ctx = protocol_new_callback_context();
  FATAL_ON(ctx == NULL);

  ctx->ep = ep;
  ctx->callback = callback;

  // Notify the secondary that client is connecting
  sl_cpc_system_cmd_property_set(on_disconnect_reply_v5,
                                 EP_ID_TO_PROPERTY_STATE(ep->id),
                                 &disconnected_state,
                                 sizeof(disconnected_state),
                                 ctx,
                                 0, // unlimited retries
                                 100000, // 100ms between retries
                                 SYSTEM_EP_IFRAME);
}

/***************************************************************************//**
 * Issue command to terminate endpoint.
 ******************************************************************************/
void terminate_endpoint_v5(sl_cpc_endpoint_t *ep,
                           on_terminate_completion_t callback)
{
  sli_cpc_endpoint_state_v5_t close_state = PROTOCOL_V5_STATE_CLOSED;
  struct protocol_callback_context *ctx;

  ctx = protocol_new_callback_context();
  FATAL_ON(ctx == NULL);

  ctx->ep = ep;
  ctx->callback = callback;

  // Notify the secondary that the endpoint should get closed
  sl_cpc_system_cmd_property_set(on_terminate_reply_v5,
                                 EP_ID_TO_PROPERTY_STATE(ep->id),
                                 &close_state,
                                 sizeof(close_state),
                                 ctx,
                                 1,      // 1 retry
                                 250000, // 250ms to receive reply
                                 SYSTEM_EP_IFRAME);
}

#if defined(ENABLE_ENCRYPTION)
void set_security_counters_v5(sl_cpc_endpoint_t *ep,
                              on_set_security_counters_completion_t callback,
                              void *cb_data)
{
  struct protocol_callback_context *ctx;
  uint8_t counters[2 * sizeof(uint32_t)];

  ctx = protocol_new_callback_context();
  FATAL_ON(ctx == NULL);

  ctx->ep = ep;
  ctx->callback = callback;
  ctx->callback_data = cb_data;

  u32_to_le(ep->frame_counter_rx, &counters[0]);
  u32_to_le(ep->frame_counter_tx, &counters[sizeof(uint32_t)]);

  sl_cpc_system_cmd_property_set(on_set_security_counters_reply_v5,
                                 EP_ID_TO_PROPERTY_ENCRYPTION(ep->id),
                                 counters,
                                 sizeof(counters),
                                 ctx,
                                 1,
                                 100000,
                                 SYSTEM_EP_IFRAME);
}
#endif
