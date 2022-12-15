/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Security Endpoint
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

#include <unistd.h>
#include <string.h>

#include "misc/logging.h"
#include "misc/sl_status.h"
#include "misc/sleep.h"
#include "server_core/server_core.h"
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
    return SL_STATUS_FAIL;
  }

  // Wait for response
  ret = cpc_read_endpoint(security_ep, buffer, sizeof(buffer), CPC_ENDPOINT_READ_FLAG_NONE);
  memcpy(response, buffer, SLI_SECURITY_PROTOCOL_HEADER_LENGTH + request_command.response_len);

  if (ret != (ssize_t)(SLI_SECURITY_PROTOCOL_HEADER_LENGTH + request_command.response_len)) {
    return SL_STATUS_FAIL;
  }

  if (response->command_id != (request_command.command_id | SLI_CPC_SECURITY_PROTOCOL_RESPONSE_MASK)) {
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

  PRINT_INFO("Unbind successful, you may restart the daemon without the --unbind argument");

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

  if (status == SL_STATUS_NOT_SUPPORTED) {
    FATAL("Secondary doesn't support this operation. If it has a Secure Element (SE), "
          "please make sure SE firmware is up to date.");
  }

  if (status != SL_STATUS_OK) {
    FATAL("ECDH exchange failed. Status = 0x%x", status);
  }

  security_keys_generate_shared_key(response.payload + sizeof(sl_status_t));

  TRACE_SECURITY("Successfully completed ECDH exchange");

  PRINT_INFO("Binding successful, you may restart the daemon without the --bind argument");

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

  PRINT_INFO("Binding successful, you may restart the daemon without the --bind argument");

  // We're done, the secondary is binded with our key
  sleep_s(1); // Wait for logs to be flushed
  exit(0);
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
    return;
  }

  session_init_response = (session_init_response_t*) protocol_response.payload;

  if (session_init_response->status != SL_STATUS_OK) {
    FATAL("The secondary failed to initialize its session");
    return;
  }

  random2 = session_init_response->random2;

  security_compute_session_key_and_id(random1, random2);

  security_session_initialized = true;

  TRACE_SECURITY("Session initialized");

  /* Notify server_core that security is ready */
  server_core_notify_security_ready();
}
