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

#ifndef SECURITY_PROTOCOL_H
#define SECURITY_PROTOCOL_H

#include "cpcd/sl_status.h"

#include "security/private/keys/keys.h"
#include "lib/sl_cpc.h"

#define SLI_SECURITY_PROTOCOL_HEADER_LENGTH (sizeof(uint16_t) + sizeof(sl_cpc_security_id_t))

SL_ENUM_GENERIC(sl_cpc_security_binding_key_method_t, uint8_t)
{
  SL_CPC_SECURITY_BINDING_KEY_CUSTOMER_SPECIFIC = 0x03,
  SL_CPC_SECURITY_BINDING_KEY_ECDH              = 0x02,
  SL_CPC_SECURITY_BINDING_KEY_PLAINTEXT_SHARE   = 0x01,
  SL_CPC_SECURITY_BINDING_KEY_NONE              = 0x00
};

#define SLI_CPC_SECURITY_BINDING_TYPE_PLAINTEXT 0x00
#define SLI_CPC_SECURITY_BINDING_TYPE_ECDH      0x01

#define SLI_CPC_SECURITY_PROTOCOL_RESPONSE_MASK 0x8000

SL_ENUM_GENERIC(sl_cpc_binding_request_t, uint8_t)
{
  PLAIN_TEXT_KEY_SHARE_BINDING_REQUEST = 0x00,
  ECDH_BINDING_REQUEST = 0x01
};

SL_ENUM_GENERIC(sl_cpc_security_id_t, uint16_t)
{
  BINDING_REQUEST_ID       = 0x0001,
  PLAIN_TEXT_KEY_SHARE_ID  = 0x0002,
  PUBLIC_KEY_SHARE_ID      = 0x0003,
  SESSION_INIT_ID          = 0x0004,
  UNBIND_REQUEST_ID        = 0x0005
};

typedef struct {
  uint16_t request_len;
  uint16_t response_len;
  sl_cpc_security_id_t command_id;
}sl_cpc_security_protocol_cmd_info_t;

#define SLI_SECURITY_PROTOCOL_PAYLOAD_MAX_LENGTH (sizeof(sl_status_t) + SESSION_INIT_RANDOM_LENGTH_BYTES)

typedef struct {
  uint16_t len;
  sl_cpc_security_id_t command_id;
  uint8_t payload[SLI_SECURITY_PROTOCOL_PAYLOAD_MAX_LENGTH];
}sl_cpc_security_protocol_cmd_t;

typedef struct {
  sl_status_t status;
  uint8_t random2[SESSION_INIT_RANDOM_LENGTH_BYTES];
}__attribute__((packed)) session_init_response_t;

sl_status_t security_send_binding_request(sl_cpc_binding_request_t binding_request, sl_cpc_security_protocol_cmd_t *response);

sl_status_t security_send_plain_text_key(uint8_t *key, sl_cpc_security_protocol_cmd_t *response);

sl_status_t security_send_public_key(uint8_t *key, sl_cpc_security_protocol_cmd_t *response);

sl_status_t security_send_unbind_request(sl_cpc_security_protocol_cmd_t *response);

sl_status_t security_send_session_init_request(uint8_t *random1, sl_cpc_security_protocol_cmd_t *response);

void security_exchange_keys(sl_cpc_binding_request_t binding_method);

void security_request_unbind(void);

void security_initialize_session(void);

void security_reset_session(void);

#endif //SECURITY_PROTOCOL_H
