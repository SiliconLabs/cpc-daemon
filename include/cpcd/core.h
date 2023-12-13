/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Server Core
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

#ifndef CPC_PROTOCOL_H
#define CPC_PROTOCOL_H

#include <time.h>

#include "cpcd/exchange.h"
#include "cpcd/sl_slist.h"
#include "cpcd/sl_status.h"

#include "sl_cpc.h"

#define SL_CPC_ENDPOINT_MAX_COUNT  256

// -----------------------------------------------------------------------------
// Data Types

SL_ENUM(sli_cpc_endpoint_state_t) {
  SLI_CPC_STATE_FREED = 0,                     ///< State freed
  SLI_CPC_STATE_OPEN,                          ///< State open
  SLI_CPC_STATE_CLOSED,                        ///< State close
  SLI_CPC_STATE_CLOSING,                       ///< State closing
  SLI_CPC_STATE_CONNECTING,                    ///< Connecting to remote's endpoint
  SLI_CPC_STATE_CONNECTED,                     ///< Connected to remote's endpoint
  SLI_CPC_STATE_SHUTTING_DOWN,                 ///< Transmissions shutting down
  SLI_CPC_STATE_SHUTDOWN,                      ///< Transmissions shut down
  SLI_CPC_STATE_REMOTE_SHUTDOWN,               ///< Remote transmissions shut down
  SLI_CPC_STATE_DISCONNECTED,                  ///< Connection terminated
  SLI_CPC_STATE_ERROR_DESTINATION_UNREACHABLE, ///< Error state, destination unreachable
  SLI_CPC_STATE_ERROR_SECURITY_INCIDENT,       ///< Error state, security incident
  SLI_CPC_STATE_ERROR_FAULT,                   ///< Error state, fault
};

typedef void (*sl_cpc_on_final_t)(uint8_t endpoint_id, void *arg, void *answer, uint32_t answer_length);

typedef void (*sl_cpc_on_data_reception_t)(uint8_t endpoint_id, const void* data, size_t data_len);

/***************************************************************************//**
 * Typedef for the callback that must be passed to `core_remote_ep_is_opened`.
 *
 * @param
 *   [in] ep_id
 *     Endpoint ID that was queried
 *
 *   [in] status
 *     SL_STATUS_OK if the endpoint is opened, other sl_status_t code otherwise.
 *
 *   [in] ctx
 *     Callback context that was passed to `core_remote_ep_is_opened`.
 ******************************************************************************/
typedef void (*on_is_open_query_completion_t)(uint8_t ep_id, sl_status_t status, void *ctx);

typedef struct {
  void *on_fnct_arg;
  sl_cpc_on_final_t on_final;
} sl_cpc_poll_final_t;

/***************************************************************************//**
 * Set the protocol version that the core should use to communicate with the
 * secondary.
 *
 * @param
 *   [in] version
 *     Version of the protocol supported by the secondary.
 *
 * @return 0 if protocol version could be set, a negative errno value otherwise.
 ******************************************************************************/
int core_set_protocol_version(uint8_t version);

/***************************************************************************//**
 * Request to open an endpoint.
 *
 * @param
 *   [in] endpoint_number
 *     ID of the endpoint to be opened.
 *
 *   [in] tx_window_size
 *     Size of the TX window.
 ******************************************************************************/
void core_open_endpoint(uint8_t endpoint_number, uint8_t tx_window_size);

/***************************************************************************//**
 * Query remote device to check if an endpoint is opened. As this operation
 * is asynchronous, a callback must be provided that will be called upon
 * completion.
 *
 * @param
 *   [in] ep_id
 *     The endpoint id to be queried.
 *
 *   [in] server_callback
 *     A callback of type `on_is_open_query_completion_t`
 *
 *   [in] server_ctx
 *     Additional context that will be passed to `server_callback`.
 ******************************************************************************/
void core_remote_ep_is_opened(uint8_t ep_id,
                              on_is_open_query_completion_t server_callback,
                              void *server_ctx);

/*
 * Internal state for the endpoints. Will be filled by cpc_register_endpoint()
 */
typedef struct endpoint {
  uint8_t id;
  uint8_t flags;
  uint8_t seq;
  uint8_t ack;
  uint8_t configured_tx_window_size;
  uint8_t current_tx_window_space;
  uint8_t frames_count_re_transmit_queue;
  uint32_t    re_transmit_timeout_ms;
  void*   re_transmit_timer_private_data;
  sli_cpc_endpoint_state_t state;
  sl_slist_node_t *re_transmit_queue;
  sl_slist_node_t *holding_list;
  sl_cpc_on_data_reception_t on_uframe_data_reception;
  sl_cpc_on_data_reception_t on_iframe_data_reception;
  sl_cpc_poll_final_t poll_final;
  struct timespec last_iframe_sent_timestamp;
  uint32_t smoothed_rtt;
  uint32_t rtt_variation;
#if defined(ENABLE_ENCRYPTION)
  bool encrypted;
  uint32_t frame_counter_tx;
  uint32_t frame_counter_rx;
#endif
} sl_cpc_endpoint_t;

#endif
