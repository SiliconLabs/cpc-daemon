/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Security Public API
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

#ifndef CPCD_SECURITY_H
#define CPCD_SECURITY_H

#include <stdint.h>
#include <stdbool.h>

#include "cpcd/core.h"
#include "cpcd/sl_status.h"

typedef enum {
  SECURITY_COMMAND_NONE,
  SECURITY_COMMAND_RECONNECT,
  SECURITY_COMMAND_PLAIN_TEXT_BINDING,
  SECURITY_COMMAND_ECDH_BINDING,
  SECURITY_COMMAND_UNBIND,
  SECURITY_COMMAND_INITIALIZE_SESSION,
  SECURITY_COMMAND_RESET_SESSION,
  SECURITY_COMMAND_KILL_THREAD
} sl_cpc_security_command_t;

typedef enum {
  SECURITY_STATE_NOT_READY,
  SECURITY_STATE_DISABLED,
  SECURITY_STATE_INITIALIZING,
  SECURITY_STATE_RESETTING,
  SECURITY_STATE_INITIALIZED,
} sl_cpc_security_state_t;

typedef struct {
  uint32_t frame_counter;
} sl_cpc_security_frame_t;

typedef void (*sl_cpc_security_on_state_change_t)(sl_cpc_security_state_t old,
                                                  sl_cpc_security_state_t new);

/***************************************************************************//**
 * Initialize the security endpoint
 ******************************************************************************/
void security_init(void);

void security_kill_signal(void);

/***************************************************************************//**
 * Unblock thread blocked on security_post_command
 ******************************************************************************/
void security_unblock_post_command(void);

/***************************************************************************//**
 * Send a security command
 ******************************************************************************/
void security_post_command(sl_cpc_security_command_t event);

/***************************************************************************//**
 * Get the state of the security subsystem
 ******************************************************************************/
sl_cpc_security_state_t security_get_state(void);

void security_register_state_change_callback(sl_cpc_security_on_state_change_t func);

sl_cpc_security_frame_t* security_encrypt_prepare_next_frame(sl_cpc_endpoint_t *ep);

sl_status_t security_encrypt(sl_cpc_endpoint_t *ep, sl_cpc_security_frame_t *sec_frame,
                             const uint8_t *header, const size_t header_len,
                             const uint8_t *payload, const size_t payload_len,
                             uint8_t *output,
                             uint8_t *tag, const size_t tag_len);

sl_status_t security_decrypt(sl_cpc_endpoint_t *ep,
                             const uint8_t *header, const size_t header_len,
                             const uint8_t *payload, const size_t payload_len,
                             uint8_t *output,
                             const uint8_t *tag, const size_t tag_len);
#if defined(UNIT_TESTING)
sl_status_t security_encrypt_secondary(sl_cpc_endpoint_t *ep,
                                       const uint8_t *header, const size_t header_len,
                                       const uint8_t *payload, const size_t payload_len,
                                       uint8_t *output,
                                       uint8_t *tag, const size_t tag_len);

sl_status_t security_decrypt_secondary(sl_cpc_endpoint_t *ep,
                                       const uint8_t *header, const size_t header_len,
                                       const uint8_t *payload, const size_t payload_len,
                                       uint8_t *output,
                                       const uint8_t *tag, const size_t tag_len);
#endif

void security_xfer_rollback(sl_cpc_endpoint_t *ep);

size_t security_encrypt_get_extra_buffer_size(void);

bool security_session_has_reset(void);

void security_session_reset_clear_flag(void);

#endif // CPCD_SECURITY_H
