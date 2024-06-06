/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Buffer Management
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

#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>

#include "cpcd/core.h"
#include "cpcd/security.h"
#include "cpcd/sl_slist.h"

typedef struct {
  uint8_t *hdlc_header;
  const uint8_t *data;
  uint16_t data_length;
  uint16_t fcs;
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

struct sl_cpc_transmit_queue_item;
typedef struct sl_cpc_transmit_queue_item sl_cpc_transmit_queue_item_t;

sl_cpc_buffer_handle_t* buffer_new(sl_cpc_endpoint_t *ep,
                                   const uint8_t ep_id,
                                   const uint8_t *data,
                                   const size_t data_len,
                                   const uint8_t control);

sl_cpc_buffer_handle_t* buffer_item_to_buffer(sl_cpc_transmit_queue_item_t *item);

sl_cpc_transmit_queue_item_t* buffer_list_pop_item(sl_slist_node_t **head);

void buffer_list_push_back_item(sl_cpc_transmit_queue_item_t *item,
                                sl_slist_node_t **head);

void buffer_release(sl_cpc_buffer_handle_t *frame);

void buffer_list_push_back(sl_cpc_buffer_handle_t *frame, sl_slist_node_t **head);

sl_cpc_buffer_handle_t* buffer_list_peek(sl_slist_node_t *head);

sl_cpc_buffer_handle_t* buffer_list_pop(sl_slist_node_t **head);

void buffer_list_clear_for_endpoint(sl_slist_node_t **head, sl_cpc_endpoint_t *ep);

void buffer_list_clear_all(sl_slist_node_t **head);
#endif
