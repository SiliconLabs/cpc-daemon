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

#include "config.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "cpcd/utils.h"
#include "cpcd/logging.h"

#include "buffer.h"
#include "crc.h"

/*******************************************************************************
 ***************************  STRUCT DEFINITION  *******************************
 ******************************************************************************/
struct sl_cpc_transmit_queue_item {
  sl_slist_node_t node;
  sl_cpc_buffer_handle_t *handle;
};

/*******************************************************************************
 **************************   IMPLEMENTATION    ********************************
 ******************************************************************************/

/***************************************************************************//**
 * Allocate a new buffer, calculating CRC on data if present
 ******************************************************************************/
sl_cpc_buffer_handle_t* buffer_new(sl_cpc_endpoint_t *ep,
                                   const uint8_t ep_id,
                                   const uint8_t *data,
                                   const size_t data_len,
                                   const uint8_t control)
{
  sl_cpc_buffer_handle_t *buffer;

  buffer = (sl_cpc_buffer_handle_t*) zalloc(sizeof(*buffer));
  if (buffer == NULL) {
    return NULL;
  }

  buffer->endpoint = ep;
  buffer->address = ep_id;
  buffer->control = control;

  if ((data != NULL) && (data_len > 0)) {
    FATAL_ON(data_len > UINT16_MAX);

    buffer->data = data;
    buffer->data_length = (uint16_t)data_len;

    buffer->fcs = sli_cpc_get_crc_sw(buffer->data, buffer->data_length);
  }

  // explicitely set ref_cnt to 0, even though
  // it already was because it was zalloc'ed
  buffer->ref_cnt = 0;

  return buffer;
}

/***************************************************************************//**
 * Release a buffer handle if it's ref count is zero
 ******************************************************************************/
void buffer_release(sl_cpc_buffer_handle_t *frame)
{
  if (frame != NULL && frame->ref_cnt == 0) {
#if defined(ENABLE_ENCRYPTION)
    if (frame->security_info) {
      free((void *)frame->security_info);
    }
#endif

    if (frame->data_length > 0) {
      free((void *)frame->data);
    }

    free(frame->hdlc_header);
    free(frame);
  }
}

/***************************************************************************//**
 * Convert a queue item to a buffer handle
 ******************************************************************************/
sl_cpc_buffer_handle_t* buffer_item_to_buffer(sl_cpc_transmit_queue_item_t *item)
{
  if (item == NULL) {
    return NULL;
  }

  return item->handle;
}

/***************************************************************************//**
 * Pop transmit queue item from a list
 ******************************************************************************/
sl_cpc_transmit_queue_item_t* buffer_list_pop_item(sl_slist_node_t **head)
{
  sl_cpc_transmit_queue_item_t *item;
  sl_slist_node_t *node;

  if (head == NULL || *head == NULL) {
    return NULL;
  }

  // Get first queued item
  node = sl_slist_pop(head);
  item = SL_SLIST_ENTRY(node, sl_cpc_transmit_queue_item_t, node);

  return item;
}

/***************************************************************************//**
 * Push back a transmit item in a list.
 ******************************************************************************/
void buffer_list_push_back_item(sl_cpc_transmit_queue_item_t *item,
                                sl_slist_node_t **head)
{
  sl_slist_push_back(head, &item->node);
}

/***************************************************************************//**
 * Remove buffer handles from a list, optionally filtering by endpoint ID.
 ******************************************************************************/
static void buffer_list_clear_common(sl_slist_node_t **head, bool filter, uint8_t ep_id)
{
  sl_slist_node_t *current_node;
  sl_slist_node_t *next_node;

  if (head == NULL || *head == NULL) {
    return;
  }

  // init current_node to the first element in the list
  current_node = *head;

  while (current_node) {
    // store next_node right away as the element containing
    // current_node might get free'd below
    next_node = current_node->node;

    sl_cpc_transmit_queue_item_t *item = SL_SLIST_ENTRY(current_node, sl_cpc_transmit_queue_item_t, node);
    if (!filter
        || (filter && item->handle->address == ep_id)) {
      item->handle->ref_cnt--;
      buffer_release(item->handle);

      // remove element from list and free it
      sl_slist_remove(head, &item->node);
      free(item);
    }

    // prepare next while iteration by moving current_node
    // to the next element in the list
    current_node = next_node;
  }
}

/***************************************************************************//**
 * Remove buffer handles that belong to a specific endpoint from a list.
 ******************************************************************************/
void buffer_list_clear_for_endpoint(sl_slist_node_t **head, sl_cpc_endpoint_t *ep)
{
  buffer_list_clear_common(head, true, ep->id);
}

/***************************************************************************//**
 * Remove all buffer handles from a list.
 ******************************************************************************/
void buffer_list_clear_all(sl_slist_node_t **head)
{
  buffer_list_clear_common(head, false, 0);
}

/***************************************************************************//**
 * Acquire a buffer handle (increase ref count) and push it back in a list
 ******************************************************************************/
void buffer_list_push_back(sl_cpc_buffer_handle_t *frame, sl_slist_node_t **head)
{
  sl_cpc_transmit_queue_item_t *item;

  item = (sl_cpc_transmit_queue_item_t*) zalloc(sizeof(*item));
  FATAL_SYSCALL_ON(item == NULL);

  item->handle = frame;

  frame->ref_cnt++;

  buffer_list_push_back_item(item, head);
}

/***************************************************************************//**
 * Peek a buffer handle from a list, without removing it from the list.
 ******************************************************************************/
sl_cpc_buffer_handle_t* buffer_list_peek(sl_slist_node_t *head)
{
  sl_cpc_transmit_queue_item_t *item;

  if (head == NULL) {
    return NULL;
  }

  item = SL_SLIST_ENTRY(head, sl_cpc_transmit_queue_item_t, node);

  return item->handle;
}

/***************************************************************************//**
 * Pop buffer handle from a list and release it (decrease its ref count)
 ******************************************************************************/
sl_cpc_buffer_handle_t* buffer_list_pop(sl_slist_node_t **head)
{
  sl_cpc_transmit_queue_item_t *item;
  sl_cpc_buffer_handle_t *buffer;

  item = buffer_list_pop_item(head);
  if (item == NULL) {
    return NULL;
  }

  buffer = item->handle;
  buffer->ref_cnt--;

  free(item);

  return buffer;
}
