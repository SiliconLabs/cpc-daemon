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

#include "sl_cpc.h"

#define SL_CPC_ENDPOINT_MAX_COUNT  256

// -----------------------------------------------------------------------------
// Data Types

typedef void (*sl_cpc_on_final_t)(uint8_t endpoint_id, void *arg, void *answer, uint32_t answer_length);

typedef struct {
  void *on_fnct_arg;
  sl_cpc_on_final_t on_final;
} sl_cpc_poll_final_t;

typedef void (*sl_cpc_on_data_reception_t)(uint8_t endpoint_id, const void* data, size_t data_len);

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
  cpc_endpoint_state_t state;
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
