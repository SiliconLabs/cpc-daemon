/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Internal Protocol Header
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

#ifndef CORE_PROTOCOL_INTERNAL_H
#define CORE_PROTOCOL_INTERNAL_H

#include "cpcd/core.h"
#include "cpcd/sl_slist.h"
#include "cpcd/sl_status.h"

#include "protocol.h"

/*
 * Structure used by protocol implementations to store context
 * when issuing a system command.
 */
struct protocol_callback_context {
  sl_cpc_endpoint_t *ep;
  void *callback;
  void *callback_data;
};

/***************************************************************************//**
 * Allocate a protocol callback context.
 *
 * @return A newly allocated `struct protocol_callback_context`, struct is memset to 0.
 *         NULL if structure could not be allocated
 ******************************************************************************/
struct protocol_callback_context* protocol_new_callback_context(void);

/***************************************************************************//**
 * Free structure allocated by `protocol_new_callback_context`
 *
 * @param
 *   [in] context
 *     Structure previously allocated
 ******************************************************************************/
void protocol_free_callback_context(struct protocol_callback_context *context);

/*******************************************************************************
 *****************************   PROTOCOL V4   *********************************
 ******************************************************************************/
sl_status_t parse_endpoint_state_v4(const uint8_t *payload,
                                    const size_t payload_len,
                                    sli_cpc_endpoint_state_t *state);
void is_endpoint_opened_v4(sl_cpc_endpoint_t *ep,
                           on_is_opened_completion_t callback,
                           void *callback_ctx);
void is_endpoint_encrypted_v4(sl_cpc_endpoint_t *ep,
                              on_is_encrypted_completion_t callback,
                              void *callback_ctx);
void connect_endpoint_v4(sl_cpc_endpoint_t *ep,
                         on_connect_completion_t callback);
void terminate_endpoint_v4(sl_cpc_endpoint_t *ep,
                           on_terminate_completion_t callback);

/*******************************************************************************
 *****************************   PROTOCOL V5   *********************************
 ******************************************************************************/
sl_status_t parse_endpoint_state_v5(const uint8_t *payload,
                                    const size_t payload_len,
                                    sli_cpc_endpoint_state_t *state);
void is_endpoint_opened_v5(sl_cpc_endpoint_t *ep,
                           on_is_opened_completion_t callback,
                           void *callback_ctx);
void is_endpoint_encrypted_v5(sl_cpc_endpoint_t *ep,
                              on_is_encrypted_completion_t callback,
                              void *callback_ctx);
void connect_endpoint_v5(sl_cpc_endpoint_t *ep,
                         on_connect_completion_t callback);
void disconnect_endpoint_v5(sl_cpc_endpoint_t *ep,
                            on_disconnect_completion_t callback);
void terminate_endpoint_v5(sl_cpc_endpoint_t *ep,
                           on_terminate_completion_t callback);
#if defined(ENABLE_ENCRYPTION)
void set_security_counters_v5(sl_cpc_endpoint_t *ep,
                              on_set_security_counters_completion_t callback,
                              void *cb_data);
#endif

#endif // CORE_PROTOCOL_INTERNAL_H
