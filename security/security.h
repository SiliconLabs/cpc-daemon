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

#ifndef SECURITY_H
#define SECURITY_H

#include <stdbool.h>

#include "misc/sl_status.h"

/***************************************************************************//**
 * Initialize the security endpoint
 ******************************************************************************/
void security_init(void);

void security_kill_signal(void);

typedef enum {
  SECURITY_COMMAND_NONE,
  SECURITY_COMMAND_RECONNECT,
  SECURITY_COMMAND_PLAIN_TEXT_BINDING,
  SECURITY_COMMAND_ECDH_BINDING,
  SECURITY_COMMAND_UNBIND,
  SECURITY_COMMAND_INITIALIZE_SESSION,
  SECURITY_COMMAND_RESET_SESSION,
  SECURITY_COMMAND_KILL_THREAD
}sl_cpc_security_command_t;

typedef enum {
  SECURITY_STATE_NOT_READY,
  SECURITY_STATE_DISABLED,
  SECURITY_STATE_INITIALIZING,
  SECURITY_STATE_RESETTING,
  SECURITY_STATE_INITIALIZED,
} sl_cpc_security_state_t;

/***************************************************************************//**
 * Send a security command
 ******************************************************************************/
void security_post_command(sl_cpc_security_command_t event);

/***************************************************************************//**
 * Get the state of the security subsystem
 ******************************************************************************/
sl_cpc_security_state_t security_get_state(void);

void security_set_state(sl_cpc_security_state_t new_state);

extern volatile bool security_session_initialized;

sl_status_t security_encrypt(const uint8_t *header, const size_t header_len,
                             const uint8_t *payload, const size_t payload_len,
                             uint8_t *output,
                             uint8_t *tag, const size_t tag_len);

sl_status_t security_decrypt(const uint8_t *header, const size_t header_len,
                             const uint8_t *payload, const size_t payload_len,
                             uint8_t *output,
                             const uint8_t *tag, const size_t tag_len);
#if defined(UNIT_TESTING)
sl_status_t security_encrypt_secondary(const uint8_t *header, const size_t header_len,
                                       const uint8_t *payload, const size_t payload_len,
                                       uint8_t *output,
                                       uint8_t *tag, const size_t tag_len);

sl_status_t security_decrypt_secondary(const uint8_t *header, const size_t header_len,
                                       const uint8_t *payload, const size_t payload_len,
                                       uint8_t *output,
                                       const uint8_t *tag, const size_t tag_len);
#endif

void security_drop_incoming_packet(void);

size_t security_encrypt_get_extra_buffer_size(void);

#endif //SECURITY_H
