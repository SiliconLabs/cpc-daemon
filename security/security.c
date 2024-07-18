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

#include "config.h"

#include <pthread.h>

#include "cpcd/config.h"
#include "cpcd/logging.h"
#include "cpcd/security.h"

#include "server_core/server/server_ready_sync.h"
#include "security/private/keys/keys.h"
#include "security/private/thread/command_synchronizer.h"
#include "security/private/thread/security_thread.h"
#include "security/security.h"

static pthread_t security_thread;
volatile bool security_session_initialized = false;

void security_init(void)
{
  int ret;

  if (config.use_encryption == false) {
    TRACE_SECURITY("Encryption is disabled");
    security_set_state_disabled();
    return;
  }

  ret = pthread_create(&security_thread, NULL, security_thread_func, NULL);
  FATAL_ON(ret != 0);

  ret = pthread_setname_np(security_thread, "security");
  FATAL_ON(ret != 0);

  TRACE_SECURITY("Thread created");
}

void security_kill(void)
{
  if (config.use_encryption == false) {
    TRACE_SECURITY("Encryption is disabled");
    return;
  }

  if (security_initialized) {
    security_post_command(SECURITY_COMMAND_KILL_THREAD);
    pthread_join(security_thread, NULL);
    security_initialized = false;
  }
}

void security_unblock_post_command(void)
{
  security_flush_pending_commands();
}

sl_status_t security_encrypt(sl_cpc_endpoint_t *ep, sl_cpc_security_frame_t *sec_frame,
                             const uint8_t *header, const size_t header_len,
                             const uint8_t *payload, const size_t payload_len,
                             uint8_t *output,
                             uint8_t *tag, const size_t tag_len)
{
  if (security_session_initialized != true) {
    return SL_STATUS_NOT_INITIALIZED;
  }

  return __security_encrypt(ep, sec_frame,
                            header, header_len,
                            payload, payload_len,
                            output,
                            tag, tag_len);
}

sl_status_t security_decrypt(sl_cpc_endpoint_t *ep,
                             const uint8_t *header, const size_t header_len,
                             const uint8_t *payload, const size_t payload_len,
                             uint8_t *output,
                             const uint8_t *tag, const size_t tag_len)
{
  if (security_session_initialized != true) {
    return SL_STATUS_NOT_INITIALIZED;
  }

  return __security_decrypt(ep,
                            header, header_len,
                            payload, payload_len,
                            output,
                            tag, tag_len);
}

#if defined(UNIT_TESTING)
sl_status_t security_encrypt_secondary(sl_cpc_endpoint_t *ep,
                                       const uint8_t *header, const size_t header_len,
                                       const uint8_t *payload, const size_t payload_len,
                                       uint8_t *output,
                                       uint8_t *tag, const size_t tag_len)
{
  if (security_session_initialized != true) {
    return SL_STATUS_NOT_INITIALIZED;
  }

  return __security_encrypt_secondary(ep,
                                      header, header_len,
                                      payload, payload_len,
                                      output,
                                      tag, tag_len);
}

sl_status_t security_decrypt_secondary(sl_cpc_endpoint_t *ep,
                                       const uint8_t *header, const size_t header_len,
                                       const uint8_t *payload, const size_t payload_len,
                                       uint8_t *output,
                                       const uint8_t *tag, const size_t tag_len)
{
  if (security_session_initialized != true) {
    return SL_STATUS_NOT_INITIALIZED;
  }

  return __security_decrypt_secondary(ep,
                                      header, header_len,
                                      payload, payload_len,
                                      output,
                                      tag, tag_len);
}
#endif

size_t security_encrypt_get_extra_buffer_size(void)
{
  return __security_encrypt_get_extra_buffer_size();
}
