/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Protocol V4 Implementation
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

#include "errno.h"

#include "cpcd/logging.h"

#include "server_core/system_endpoint/system.h"

#include "protocol.h"
#include "protocol_internal.h"

/*
 * Enum with all endpoint states supported by this protocol.
 */
SL_ENUM(sli_cpc_endpoint_state_v4_t) {
  PROTOCOL_V4_STATE_OPEN = 0,
  PROTOCOL_V4_STATE_CLOSED,
  PROTOCOL_V4_STATE_CLOSING,
  PROTOCOL_V4_STATE_ERROR_DESTINATION_UNREACHABLE,
  PROTOCOL_V4_STATE_ERROR_SECURITY_INCIDENT,
  PROTOCOL_V4_STATE_ERROR_FAULT,
  PROTOCOL_V4_STATE_FREED,
};

/***************************************************************************//**
 * Convert an endpoint state to string.
 ******************************************************************************/
static const char* protocol_state_to_str(sli_cpc_endpoint_state_v4_t state)
{
  switch (state) {
    case PROTOCOL_V4_STATE_OPEN:
      return "OPEN";
    case PROTOCOL_V4_STATE_CLOSED:
      return "CLOSED";
    case PROTOCOL_V4_STATE_CLOSING:
      return "CLOSING";
    case PROTOCOL_V4_STATE_ERROR_DESTINATION_UNREACHABLE:
      return "ERROR_DESTINATION_UNREACHABLE";
    case PROTOCOL_V4_STATE_ERROR_SECURITY_INCIDENT:
      return "ERROR_SECURITY_INCIDENT";
    case PROTOCOL_V4_STATE_ERROR_FAULT:
      return "ERROR_FAULT";
    case PROTOCOL_V4_STATE_FREED:
      return "FREED";
    default:
      return "UNKNOWN";
  }
}

/***************************************************************************//**
 * Callback called when the endpoint state is received.
 ******************************************************************************/
static void is_endpoint_opened_reply_v4(sli_cpc_property_id_t property_id,
                                        void *property_value,
                                        size_t property_length,
                                        void *user_data,
                                        sl_status_t status)
{
  struct protocol_callback_context *ctx = (struct protocol_callback_context*)user_data;
  sli_cpc_endpoint_state_v4_t remote_endpoint_state;
  on_is_opened_completion_t callback;
  bool secondary_reachable = false;
  uint8_t endpoint_id;

  FATAL_ON(ctx == NULL);
  callback = (on_is_opened_completion_t)ctx->callback;

  endpoint_id = PROPERTY_ID_TO_EP_ID(property_id);

  /* Sanity checks */
  {
    /* This function's signature is for all properties get/set. Make sure we
     * are dealing with PROP_ENDPOINT_STATE and with the correct property_length*/
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
    if (remote_endpoint_state == PROTOCOL_V4_STATE_OPEN) {
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

static void is_endpoint_encrypted_reply_v4(sli_cpc_property_id_t property_id,
                                           void *property_value,
                                           size_t property_length,
                                           void *user_data,
                                           sl_status_t status)
{
  struct protocol_callback_context *ctx = (struct protocol_callback_context*)user_data;
  on_is_encrypted_completion_t callback;
  bool secondary_reachable = false;
  uint8_t endpoint_id = 0;
  bool encryption = false;

  FATAL_ON(ctx == NULL);
  callback = (on_is_encrypted_completion_t)ctx->callback;

  switch (status) {
    case SL_STATUS_OK:
    case SL_STATUS_IN_PROGRESS:
      TRACE_CORE("Property-get::PROP_ENDPOINT_ENCRYPTION Successful callback");
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

  if (secondary_reachable) {
    if (property_length != sizeof(bool)) {
      status = SL_STATUS_INVALID_TYPE;
    } else if (property_id >= EP_ID_TO_PROPERTY_ENCRYPTION(0)
               && property_id <= EP_ID_TO_PROPERTY_ENCRYPTION(255)) {
      endpoint_id = PROPERTY_ID_TO_EP_ID(property_id);

      if (endpoint_id == ctx->ep->id) {
        encryption = *((bool*)property_value);
        status = SL_STATUS_OK;

        TRACE_CORE("Secondary has per-endpoint encryption: ep#%d: encryption=%d",
                   endpoint_id, encryption);
      } else {
        TRACE_CORE("Reply doesn't match the right endpoint. Got %d, expected %d",
                   endpoint_id, ctx->ep->id);
        status = SL_STATUS_INVALID_PARAMETER;
      }
    } else {
      status = SL_STATUS_FAIL;

      TRACE_CORE("Could not read endpoint encryption state for ep#%d on the secondary",
                 ctx->ep->id);
    }
  } else {
    status = SL_STATUS_FAIL;
  }

  callback(ctx->ep, status, encryption, ctx->callback_data);

  protocol_free_callback_context(ctx);
}

/***************************************************************************//**
 * Callback called when a response to a `connect` is received.
 ******************************************************************************/
static void on_connect_reply_v4(sli_cpc_property_id_t property_id,
                                void *property_value,
                                size_t property_length,
                                void *user_data,
                                sl_status_t status)
{
  struct protocol_callback_context *ctx = (struct protocol_callback_context*)user_data;
  uint8_t ep_id = PROPERTY_ID_TO_EP_ID(property_id);
  on_connect_completion_t callback;

  (void)property_value;

  FATAL_ON(ctx == NULL);

  callback = (on_connect_completion_t)ctx->callback;

  switch (status) {
    case SL_STATUS_IN_PROGRESS:
    case SL_STATUS_OK:
      if (property_length != 0) {
        TRACE_CORE("Connection confirmation for ep#%d has invalid length (expected %d, got %d)",
                   ep_id, 0, property_length);
        callback(ctx->ep, SL_STATUS_INVALID_TYPE);
        break;
      }

      callback(ctx->ep, SL_STATUS_OK);
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
 * Callback called when the response to a `terminate` is received.
 ******************************************************************************/
static void on_terminate_reply_v4(sli_cpc_property_id_t property_id,
                                  void *property_value,
                                  size_t property_length,
                                  void *user_arg,
                                  sl_status_t status)
{
  struct protocol_callback_context *ctx = (struct protocol_callback_context*)user_arg;
  uint8_t ep_id = PROPERTY_ID_TO_EP_ID(property_id);
  on_terminate_completion_t callback;

  (void)property_value;

  FATAL_ON(ctx == NULL);

  callback = (on_terminate_completion_t)ctx->callback;

  switch (status) {
    case SL_STATUS_IN_PROGRESS:
    case SL_STATUS_OK:
      TRACE_CORE("Terminate reply received for ep#%d", ep_id);

      if (property_length != 0) {
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

/***************************************************************************//**
 * Convert bytestream to internal core state.
 ******************************************************************************/
sl_status_t parse_endpoint_state_v4(const uint8_t *payload,
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
    case PROTOCOL_V4_STATE_OPEN:
    case PROTOCOL_V4_STATE_CLOSED:
    case PROTOCOL_V4_STATE_CLOSING:
    case PROTOCOL_V4_STATE_ERROR_DESTINATION_UNREACHABLE:
    case PROTOCOL_V4_STATE_ERROR_SECURITY_INCIDENT:
    case PROTOCOL_V4_STATE_ERROR_FAULT:
    case PROTOCOL_V4_STATE_FREED:
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
void is_endpoint_opened_v4(sl_cpc_endpoint_t *ep,
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
  sl_cpc_system_cmd_property_get(is_endpoint_opened_reply_v4,
                                 EP_ID_TO_PROPERTY_STATE(ep->id),
                                 ctx,
                                 5,
                                 100000,
                                 SYSTEM_EP_IFRAME);
}

/***************************************************************************//**
 * Issue command to get endpoint encryption state
 ******************************************************************************/
void is_endpoint_encrypted_v4(sl_cpc_endpoint_t *ep,
                              on_is_encrypted_completion_t callback,
                              void *callback_ctx)
{
  struct protocol_callback_context *ctx;

  ctx = protocol_new_callback_context();
  FATAL_ON(ctx == NULL);

  ctx->ep = ep;
  ctx->callback = callback;
  ctx->callback_data = callback_ctx;

  sl_cpc_system_cmd_property_get(is_endpoint_encrypted_reply_v4,
                                 EP_ID_TO_PROPERTY_ENCRYPTION(ep->id),
                                 ctx,
                                 1,
                                 100000,
                                 SYSTEM_EP_IFRAME);
}

/***************************************************************************//**
 * Issue command to connect to endpoint.
 ******************************************************************************/
void connect_endpoint_v4(sl_cpc_endpoint_t *ep,
                         on_connect_completion_t callback)
{
  sli_cpc_endpoint_state_v4_t open_state = PROTOCOL_V4_STATE_OPEN;
  struct protocol_callback_context *ctx;

  ctx = protocol_new_callback_context();
  FATAL_ON(ctx == NULL);

  ctx->ep = ep;
  ctx->callback = callback;

  // Notify the secondary that client is connecting
  sl_cpc_system_cmd_property_set(on_connect_reply_v4,
                                 EP_ID_TO_PROPERTY_STATE(ep->id),
                                 &open_state,
                                 sizeof(open_state),
                                 ctx,
                                 0, /* unlimited retries */
                                 100000, /* 100ms between retries*/
                                 SYSTEM_EP_IFRAME);
}

/***************************************************************************//**
 * Issue command to terminate endpoint.
 ******************************************************************************/
void terminate_endpoint_v4(sl_cpc_endpoint_t *ep,
                           on_terminate_completion_t callback)
{
  sli_cpc_endpoint_state_v4_t close_state = PROTOCOL_V4_STATE_CLOSING;
  struct protocol_callback_context *ctx;

  ctx = protocol_new_callback_context();
  FATAL_ON(ctx == NULL);

  ctx->ep = ep;
  ctx->callback = callback;

  // Notify the secondary that the endpoint should get closed
  sl_cpc_system_cmd_property_set(on_terminate_reply_v4,
                                 EP_ID_TO_PROPERTY_STATE(ep->id),
                                 &close_state,
                                 sizeof(close_state),
                                 ctx,
                                 1,      /* 1 retry */
                                 100000, /* 100ms between retries*/
                                 SYSTEM_EP_IFRAME);
}
