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

#ifndef CORE_PRIVATE_H
#define CORE_PRIVATE_H

#include <time.h>

#include "cpcd/core.h"
#include "cpcd/exchange.h"
#include "cpcd/security.h"
#include "cpcd/sl_slist.h"

#include "sl_cpc.h"
#include "hdlc.h"

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
#define SLI_CPC_MAX_ROUND_TRIP_TIME_MS 5000

#define TRANSMIT_WINDOW_MIN_SIZE  1u
#define TRANSMIT_WINDOW_MAX_SIZE  7u

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

void core_process_endpoint_change(uint8_t endpoint_number, cpc_endpoint_state_t ep_state, bool encryption, uint8_t tx_window_size);

bool core_ep_is_closing(uint8_t ep_id);

void core_set_endpoint_in_error(uint8_t endpoint_number, cpc_endpoint_state_t new_state);

void core_set_endpoint_option(uint8_t endpoint_number,
                              sl_cpc_endpoint_option_t option,
                              void *value);
// -----------------------------------------------------------------------------
// Data Types

typedef struct {
  void *hdlc_header;
  const void *data;
  uint16_t data_length;
  uint8_t fcs[2];
  uint8_t control;
  uint8_t address;
  uint8_t ref_cnt;
  uint8_t re_transmit_count;
  sl_cpc_endpoint_t *endpoint;
#if defined(ENABLE_ENCRYPTION)
  bool security_session_last_packet;
  sl_cpc_security_frame_t *security_info;
#endif
} sl_cpc_buffer_handle_t;

typedef struct {
  sl_slist_node_t node;
  sl_cpc_buffer_handle_t *handle;
} sl_cpc_transmit_queue_item_t;

/* 1-byte aligned
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  header[7]  |                                                 |
 * +-+-+-+-+-+-+-+                                                 :
 * |                            payload                            |
 * :                                                               :
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct {
  uint8_t  header[SLI_CPC_HDLC_HEADER_RAW_SIZE];
  uint8_t  payload[];     // last two bytes are little endian 16bits
} frame_t;

#endif // CORE_PRIVATE_H
