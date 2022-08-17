/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Security Endpoint
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

#include <unistd.h>
#include <string.h>

#include "misc/logging.h"
#include "misc/sl_status.h"
#include "misc/sleep.h"
#include "server_core/system_endpoint/system.h"
#include "security/private/thread/security_thread.h"
#include "security/private/protocol/protocol.h"
#include "security/private/keys/keys.h"
#include "security/security.h"

const sl_cpc_security_protocol_cmd_info_t sli_cpc_security_command[] = {
  [BINDING_REQUEST_ID] =  {
    .request_len = sizeof(sl_cpc_security_binding_key_method_t),
    .response_len = sizeof(sl_status_t),
    .command_id = BINDING_REQUEST_ID
  },
  [PLAIN_TEXT_KEY_SHARE_ID] =  {
    .request_len = BINDING_KEY_LENGTH_BYTES,
    .response_len = sizeof(sl_status_t),
    .command_id = PLAIN_TEXT_KEY_SHARE_ID
  },
  [PUBLIC_KEY_SHARE_ID] =  {
    .request_len = PUBLIC_KEY_LENGTH_BYTES,
    .response_len = sizeof(sl_status_t) + PUBLIC_KEY_LENGTH_BYTES,
    .command_id = PUBLIC_KEY_SHARE_ID
  },
  [SESSION_INIT_ID] =  {
    .request_len = SESSION_INIT_RANDOM_LENGTH_BYTES,
    .response_len = sizeof(sl_status_t) + SESSION_INIT_RANDOM_LENGTH_BYTES,
    .command_id = SESSION_INIT_ID
  },
  [UNBIND_REQUEST_ID] =  {
    .request_len = 0x0000,
    .response_len = sizeof(sl_status_t),
    .command_id = UNBIND_REQUEST_ID
  },
};

static sl_status_t send_request(sl_cpc_security_protocol_cmd_info_t request_command, uint8_t *payload, size_t payload_size, sl_cpc_security_protocol_cmd_t *response)
{
  ssize_t ret;
  sl_cpc_security_protocol_cmd_t request;
  uint8_t buffer[SL_CPC_READ_MINIMUM_SIZE];

  FATAL_ON(security_initialized == false);
  FATAL_ON(request_command.request_len != payload_size);

  request.command_id = request_command.command_id;
  request.len = request_command.request_len;

  if (payload_size > 0) {
    FATAL_ON(payload == NULL);
    memcpy(request.payload, payload, payload_size);
  }

  ret = cpc_write_endpoint(security_ep, &request,
                           SLI_SECURITY_PROTOCOL_HEADER_LENGTH
                           + request_command.request_len, 0);

  if (ret != (ssize_t)(SLI_SECURITY_PROTOCOL_HEADER_LENGTH + request_command.request_len)) {
    need_reconnect = true;
    return SL_STATUS_FAIL;
  }

  // Wait for response
  ret = cpc_read_endpoint(security_ep, buffer, sizeof(buffer), 0u);
  memcpy(response, buffer, SLI_SECURITY_PROTOCOL_HEADER_LENGTH + request_command.response_len);

  if (ret != (ssize_t)(SLI_SECURITY_PROTOCOL_HEADER_LENGTH + request_command.response_len)) {
    need_reconnect = true;
    return SL_STATUS_FAIL;
  }

  if (response->command_id != (request_command.command_id | SLI_CPC_SECURITY_PROTOCOL_RESPONSE_MASK)) {
    need_reconnect = true;
    return SL_STATUS_FAIL;
  }

  return SL_STATUS_OK;
}

sl_status_t security_send_binding_request(sl_cpc_binding_request_t binding_request, sl_cpc_security_protocol_cmd_t *response)
{
  return send_request(sli_cpc_security_command[BINDING_REQUEST_ID],
                      &binding_request,
                      sizeof(sl_cpc_binding_request_t),
                      response);
}

sl_status_t security_send_plain_text_key(uint8_t *key, sl_cpc_security_protocol_cmd_t *response)
{
  return send_request(sli_cpc_security_command[PLAIN_TEXT_KEY_SHARE_ID],
                      key,
                      BINDING_KEY_LENGTH_BYTES,
                      response);
}

sl_status_t security_send_public_key(uint8_t *key, sl_cpc_security_protocol_cmd_t *response)
{
  return send_request(sli_cpc_security_command[PUBLIC_KEY_SHARE_ID],
                      key,
                      PUBLIC_KEY_LENGTH_BYTES,
                      response);
}

sl_status_t security_send_unbind_request(sl_cpc_security_protocol_cmd_t *response)
{
  return send_request(sli_cpc_security_command[UNBIND_REQUEST_ID],
                      NULL,
                      0,
                      response);
}

sl_status_t security_send_session_init_request(uint8_t *random1, sl_cpc_security_protocol_cmd_t *response)
{
  return send_request(sli_cpc_security_command[SESSION_INIT_ID],
                      random1,
                      SESSION_INIT_RANDOM_LENGTH_BYTES,
                      response);
}

void security_request_unbind(void)
{
  sl_status_t status;
  sl_cpc_security_protocol_cmd_t response;

  TRACE_SECURITY("Unbind with the secondary");
  status = security_send_unbind_request(&response);
  if (status != SL_STATUS_OK) {
    FATAL("Failed request unbind with the secondary. Status = 0x%x", status);
  }

  memcpy(&status, &response.payload, sizeof(status));
  if (status != SL_STATUS_OK) {
    if (status == SL_STATUS_NOT_INITIALIZED) {
      WARN("The secondary was already not bound");
    } else {
      if (status == SL_STATUS_PERMISSION) {
        FATAL("Failed to unbind. Remote denied the request");
      }
      FATAL("Failed to unbind with the remote. Status = 0x%x", status);
    }
  }

  TRACE_SECURITY("Successfully completed unbind with the remote");

  // We're done
  sleep_s(1); // Wait for logs to be flushed
  exit(0);
}

void security_exchange_ecdh_binding_key(void)
{
  sl_status_t status;
  sl_cpc_security_protocol_cmd_t response;

  TRACE_SECURITY("Sending ECDH binding request");
  status = security_send_binding_request(ECDH_BINDING_REQUEST, &response);
  if (status != SL_STATUS_OK) {
    FATAL("Failed to request ECDH binding with the secondary. Status = 0x%x", status);
  }

  memcpy(&status, &response.payload, sizeof(status));
  if (status != SL_STATUS_OK) {
    if (status == SL_STATUS_ALREADY_INITIALIZED) {
      FATAL("Secondary is already bound. If you want to re-bind, you need to unbind first");
    } else {
      FATAL("Secondary does not support ECDH key binding. Status = 0x%x", status);
    }
  }

  TRACE_SECURITY("Sending public key");
  status = security_send_public_key(security_keys_get_ecdh_public_key(), &response);
  if (status != SL_STATUS_OK) {
    FATAL("Failed to send public key. Status = 0x%x", status);
  }
  TRACE_SECURITY("Successfully sent public key and received public key from remote");

  FATAL_ON(response.len != (sizeof(status) + PUBLIC_KEY_LENGTH_BYTES));
  memcpy(&status, response.payload, sizeof(status));

  if (status == SL_STATUS_ALREADY_INITIALIZED) {
    FATAL("Failed to bind, secondary is already binded. Unbind first");
  }

  if (status == SL_STATUS_INVALID_MODE) {
    FATAL("Failed to bind, secondary is not configured for ECDH binding");
  }

  if (status != SL_STATUS_OK) {
    FATAL("ECDH exchange failed. Status = 0x%x", status);
  }

  security_keys_generate_shared_key(response.payload + sizeof(sl_status_t));

  TRACE_SECURITY("Successfully completed ECDH exchange");

  // We're done
  sleep_s(1); // Wait for logs to be flushed
  exit(0);
}

void security_exchange_plain_text_binding_key(uint8_t* const binding_key)
{
  sl_status_t status;
  sl_cpc_security_protocol_cmd_t response;

  TRACE_SECURITY("Sending plain text binding request");
  status = security_send_binding_request(PLAIN_TEXT_KEY_SHARE_BINDING_REQUEST, &response);
  if (status != SL_STATUS_OK) {
    FATAL("Failed to request plain text binding with the secondary. Status = 0x%x", status);
  }

  memcpy(&status, &response.payload, sizeof(status));
  if (status != SL_STATUS_OK) {
    FATAL("Secondary does not support plain text binding. Status = 0x%x", status);
  }

  TRACE_SECURITY("Sending plain text key");
  status = security_send_plain_text_key(binding_key, &response);
  if (status != SL_STATUS_OK) {
    FATAL("Failed to send plain text key. Status = 0x%x", status);
  }

  memcpy(&status, &response.payload, sizeof(status));

  //TODO:
  if (status == SL_STATUS_ALREADY_EXISTS) {
    FATAL("Failed to bind, secondary is already binded. Unbind first");
  }

  if (status == SL_STATUS_INVALID_MODE) {
    FATAL("Failed to bind, secondary is not configured for plain text binding");
  }

  if (status != SL_STATUS_OK) {
    FATAL("Failed to bind using plain text key. Status = 0x%x", status);
  }

  TRACE_SECURITY("Successfully sent plain text key");

  // We're done, the secondary is binded with our key
  sleep_s(1); // Wait for logs to be flushed
  exit(0);
}

static void security_property_get_state_callback(sl_cpc_system_command_handle_t *handle,
                                                 sl_cpc_property_id_t property_id,
                                                 void* property_value,
                                                 size_t property_length,
                                                 sl_status_t status)
{
  (void)handle;
  (void)property_value;

  // The security state of the secondary is not currently used.
  // By receiving a response from the property get command we validate
  // that the link is encrypted because it was sent as an I-Frame

  // Secondary prior to v4.1.1 will return property_value STATUS_UNIMPLEMENTED
  // combined with property_id PROP_LAST_STATUS
  FATAL_ON(property_id != PROP_SECURITY_STATE && property_id != PROP_LAST_STATUS);

  if (status != SL_STATUS_OK && status != SL_STATUS_IN_PROGRESS) {
    FATAL("Failed to get security state on the remote. Possible binding key mismatch!");
  }

  FATAL_ON(property_length != sizeof(uint32_t));
}

static void security_fetch_remote_security_state(void)
{
  sl_cpc_system_cmd_property_get(security_property_get_state_callback,
                                 PROP_SECURITY_STATE,
                                 1,
                                 1000000, // 1 second timeout
                                 false);  // Must be an i-frame to validate the encrypted link
}

void security_initialize_session(void)
{
  int ret;
  sl_status_t status;
  uint8_t random1[SESSION_INIT_RANDOM_LENGTH_BYTES];
  uint8_t *random2;
  sl_cpc_security_protocol_cmd_t protocol_response;

  session_init_response_t *session_init_response;

  ret = mbedtls_ctr_drbg_random(security_keys_get_rng_context(),
                                random1,
                                sizeof(random1));
  FATAL_ON(ret != 0);

  /* Send random1 and receive random 2 */
  status = security_send_session_init_request(random1, &protocol_response);

  if (status != SL_STATUS_OK) {
    FATAL("Sending session init request failed.");
    need_reconnect = true;
    return;
  }

  session_init_response = (session_init_response_t*) protocol_response.payload;

  if (session_init_response->status != SL_STATUS_OK) {
    FATAL("The secondary failed to initialize its session");
    need_reconnect = true;
    return;
  }

  random2 = session_init_response->random2;

  security_compute_session_key_and_id(random1, random2);

  security_session_initialized = true;

  TRACE_SECURITY("Session initialized");

#ifndef UNIT_TESTING
  security_fetch_remote_security_state();
#endif
}
