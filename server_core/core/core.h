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

#include "sl_cpc.h"

#include "hdlc.h"
#include "misc/sl_slist.h"
#include "server_core/cpcd_exchange.h"

#define SL_CPC_OPEN_ENDPOINT_FLAG_IFRAME_DISABLE    0x01 << 0   // I-frame is enabled by default; This flag MUST be set to disable the i-frame support by the endpoint
#define SL_CPC_OPEN_ENDPOINT_FLAG_UFRAME_ENABLE     0x01 << 1   // U-frame is disabled by default; This flag MUST be set to enable u-frame support by the endpoint
#define SL_CPC_OPEN_ENDPOINT_FLAG_UFRAME_INFORMATION_DISABLE  0x01 << 2

#define SL_CPC_FLAG_UNNUMBERED_INFORMATION      0x01 << 1
#define SL_CPC_FLAG_UNNUMBERED_POLL             0x01 << 2
#define SL_CPC_FLAG_UNNUMBERED_RESET_COMMAND    0x01 << 3
#define SL_CPC_FLAG_INFORMATION_POLL            0x01 << 4

// Maximum number of retry while sending a frame
#define SLI_CPC_RE_TRANSMIT 10
#define SL_CPC_MAX_RE_TRANSMIT_TIMEOUT_MS 5000
#define SL_CPC_MIN_RE_TRANSMIT_TIMEOUT_MS 5
#define SL_CPC_MIN_RE_TRANSMIT_TIMEOUT_MINIMUM_VARIATION_MS  5

#define TRANSMIT_WINDOW_MIN_SIZE  1u
#define TRANSMIT_WINDOW_MAX_SIZE  1u

#define SL_CPC_VERSION_MAJOR 1u
#define SL_CPC_VERSION_MINOR 1u

#define SL_CPC_ENDPOINT_MAX_COUNT  256

void core_init(int driver_fd, int driver_notify_fd);

void core_open_endpoint(uint8_t endpoit_number, uint8_t flags, uint8_t tx_window_size, bool encryption);

void core_process_transmit_queue(void);

#ifdef UNIT_TESTING
void core_reset_endpoint(uint8_t endpoint_number);
uint32_t core_endpoint_get_frame_counter(uint8_t endpoint_number, bool tx);
void core_endpoint_set_frame_counter(uint8_t endpoint_number, uint32_t new_value, bool tx);
#endif

void core_reset_endpoint_sequence(uint8_t endpoint_number);

bool core_ep_is_busy(uint8_t ep_id);

sl_status_t core_close_endpoint(uint8_t endpoint_number, bool notify_secondary, bool force_close);

cpc_endpoint_state_t core_get_endpoint_state(uint8_t ep_id);

bool core_get_endpoint_encryption(uint8_t ep_id);

void core_set_endpoint_state(uint8_t ep_id, cpc_endpoint_state_t state);

cpc_endpoint_state_t core_state_mapper(uint8_t state);

const char* core_stringify_state(cpc_endpoint_state_t state);

void core_write(uint8_t endpoint_number, const void* message, size_t message_len, uint8_t flags);

SL_ENUM(sl_cpc_endpoint_option_t){
  SL_CPC_ENDPOINT_ON_IFRAME_RECEIVE = 0,
  SL_CPC_ENDPOINT_ON_IFRAME_RECEIVE_ARG,
  SL_CPC_ENDPOINT_ON_UFRAME_RECEIVE,
  SL_CPC_ENDPOINT_ON_UFRAME_RECEIVE_ARG,
  SL_CPC_ENDPOINT_ON_IFRAME_WRITE_COMPLETED,
  SL_CPC_ENDPOINT_ON_IFRAME_WRITE_COMPLETED_ARG,
  SL_CPC_ENDPOINT_ON_UFRAME_WRITE_COMPLETED,
  SL_CPC_ENDPOINT_ON_UFRAME_WRITE_COMPLETED_ARG,
  SL_CPC_ENDPOINT_ON_POLL,
  SL_CPC_ENDPOINT_ON_POLL_ARG,
  SL_CPC_ENDPOINT_ON_FINAL,
  SL_CPC_ENDPOINT_ON_FINAL_ARG,
};

void core_process_endpoint_change(uint8_t endpoint_number, cpc_endpoint_state_t ep_state, bool encryption);

bool core_ep_is_closing(uint8_t ep_id);

void core_set_endpoint_in_error(uint8_t endpoint_number, cpc_endpoint_state_t new_state);

void core_set_endpoint_option(uint8_t endpoint_number,
                              sl_cpc_endpoint_option_t option,
                              void *value);
// -----------------------------------------------------------------------------
// Data Types

typedef void (*sl_cpc_on_final_t)(uint8_t endpoint_id, void *arg, void *answer, uint32_t answer_lenght);

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
  uint8_t packet_re_transmit_count;
  long    re_transmit_timeout_ms;
  void*   re_transmit_timer_private_data;
  cpc_endpoint_state_t state;
  sl_slist_node_t *re_transmit_queue;
  sl_slist_node_t *holding_list;
  sl_cpc_on_data_reception_t on_uframe_data_reception;
  sl_cpc_on_data_reception_t on_iframe_data_reception;
  sl_cpc_poll_final_t poll_final;
  struct timespec last_iframe_sent_timestamp;
  long smoothed_rtt;
  long rtt_variation;
#if defined(ENABLE_ENCRYPTION)
  bool encrypted;
  uint32_t frame_counter_tx;
  uint32_t frame_counter_rx;
#endif
}sl_cpc_endpoint_t;

typedef struct {
  uint32_t frame_counter;
} sl_cpc_security_frame_t;

typedef struct {
  void *hdlc_header;
  const void *data;
  uint16_t data_length;
  uint8_t fcs[2];
  uint8_t control;
  uint8_t address;
  sl_cpc_endpoint_t *endpoint;
#if defined(ENABLE_ENCRYPTION)
  bool security_session_last_packet;
  sl_cpc_security_frame_t *security_info;
#endif
  uint8_t pending_ack;
  bool acked;
  bool pending_tx_complete;
} sl_cpc_buffer_handle_t;

typedef struct {
  sl_slist_node_t node;
  sl_cpc_buffer_handle_t *handle;
} sl_cpc_transmit_queue_item_t;

typedef struct {
  uint8_t  header[SLI_CPC_HDLC_HEADER_RAW_SIZE];
  uint8_t  payload[];     // last two bytes are little endian 16bits
}frame_t;

#endif
