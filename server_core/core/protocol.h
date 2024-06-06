/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Protocol Header
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

#ifndef CORE_PROTOCOL_H
#define CORE_PROTOCOL_H

#include "cpcd/core.h"
#include "cpcd/sl_slist.h"
#include "cpcd/sl_status.h"

/// Callback when checking if an endpoint is opened completes
typedef void (*on_is_opened_completion_t)(sl_cpc_endpoint_t *ep, sl_status_t status, void *ctx);

/// Callback when checking for endpoint encryption completes
typedef void (*on_is_encrypted_completion_t)(sl_cpc_endpoint_t *ep, sl_status_t status, bool encrypted, void *ctx);

/// Callback when a connection completes
typedef void (*on_connect_completion_t)(sl_cpc_endpoint_t *ep, sl_status_t status);

/// Callback when a disconnection completes
typedef void (*on_disconnect_completion_t)(sl_cpc_endpoint_t *ep, sl_status_t status);

/// Called when a termine operation completes
typedef void (*on_terminate_completion_t)(sl_cpc_endpoint_t *ep, sl_status_t status);

/// Called when setting the security counters completes
typedef void (*on_set_security_counters_completion_t)(sl_cpc_endpoint_t *ep,
                                                      sl_status_t status,
                                                      void *ctx);

/// @brief Struct for storing protocol operation structure
struct protocol_ops {
  /// protocol version supported
  uint8_t         version;

  /// parse bytestream and convert it to endpoint state
  sl_status_t     (*parse_endpoint_state)(const uint8_t *payload,
                                          const size_t payload_len,
                                          sli_cpc_endpoint_state_t *state);

  /// check if endpoint is ready to be opened
  void            (*is_opened)(sl_cpc_endpoint_t *ep,
                               on_is_opened_completion_t,
                               void *ctx);

  /// get endpoint encryption state
  void            (*is_encrypted)(sl_cpc_endpoint_t *ep,
                                  on_is_encrypted_completion_t,
                                  void *ctx);

  /// connect an endpoint
  void            (*connect)(sl_cpc_endpoint_t *ep,
                             on_connect_completion_t);
  /// disconnect an endpoint
  void            (*disconnect)(sl_cpc_endpoint_t *ep,
                                on_disconnect_completion_t);

  /// terminate/close an endpoint
  void            (*terminate)(sl_cpc_endpoint_t *ep,
                               on_terminate_completion_t);

#if defined(ENABLE_ENCRYPTION)
  void            (*set_security_counters)(sl_cpc_endpoint_t *ep,
                                           on_set_security_counters_completion_t,
                                           void *ctx);
#endif
};

/***************************************************************************//**
 * @Brief Initialize protocol version component
 ******************************************************************************/
void protocol_init(void);

/***************************************************************************//**
 * @brief Retrieve a protocol operation structure.
 *
 * @param[in] protocol version requested
 *
 * @return a protocol operation structure, or NULL if not found
 ******************************************************************************/
struct protocol_ops* protocol_get(uint8_t version);

#endif // CORE_PROTOCOL_H
