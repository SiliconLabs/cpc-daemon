/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Server Core
 * @version 3.2.0
 *******************************************************************************
 * # License
 * <b>Copyright 2021 Silicon Laboratories Inc. www.silabs.com</b>
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

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>

#include "log.h"
#include "utils.h"
#include "endianess.h"
#include "core.h"
#include "crc.h"
#include "hdlc.h"
#include "sl_status.h"
#include "cpc_interface.h"
#include "server_internal.h"
#include "epoll.h"
#include "server.h"

#if defined(TARGET_TESTING)
#include "cpc_test_cmd.h"
#endif

#if defined(UNIT_TESTING)
#include "cpc_unity_common.h"
#endif

#if defined(UNIT_TESTING) || defined(TARGET_TESTING)
#define USE_ON_WRITE_COMPLETE
#endif

/*******************************************************************************
 ***************************  LOCAL DECLARATIONS   *****************************
 ******************************************************************************/

/*******************************************************************************
 ***************************  LOCAL VARIABLES   ********************************
 ******************************************************************************/

static int               driver_sock_fd;
static sl_cpc_endpoint_t core_endpoints[256];
static sl_slist_node_t   *transmit_queue = NULL;

/*******************************************************************************
 **************************   LOCAL FUNCTIONS   ********************************
 ******************************************************************************/

static void core_process_rx_driver(epoll_private_data_t *event_private_data);
static void core_process_ep_timeout(epoll_private_data_t *event_private_data);

static void core_process_rx_i_frame(frame_t *rx_frame);
static void core_process_rx_s_frame(frame_t *rx_frame);
static void core_process_rx_u_frame(frame_t *rx_frame);

/* CPC core functions  */
static bool core_process_tx_queue(void);
static void process_ack(sl_cpc_endpoint_t *endpoint, uint8_t ack);
static void transmit_ack(sl_cpc_endpoint_t *endpoint);
static void re_transmit_frame(sl_cpc_endpoint_t *endpoint);
static bool is_seq_valid(uint8_t seq, uint8_t ack);
static sl_cpc_endpoint_t* find_endpoint(uint8_t endpoint_number);
static void transmit_reject(sl_cpc_endpoint_t *endpoint, uint8_t address, uint8_t ack, sl_cpc_reject_reason_t reason);

/* Functions to operate on linux fd timers */
static void stop_re_transmit_timer(sl_cpc_endpoint_t* endpoint);
static void start_re_transmit_timer(sl_cpc_endpoint_t* endpoint);

/* Functions to communicate with the driver and server */
static void  core_push_frame_to_driver(const void *frame, size_t frame_len);
static void core_pull_frame_from_driver(frame_t** frame_buf, size_t* frame_buf_len);

static void core_push_data_to_server(uint8_t ep_id, const void *data, size_t data_len);

/*******************************************************************************
 **************************   IMPLEMENTATION    ********************************
 ******************************************************************************/
void core_init(int driver_fd)
{
  driver_sock_fd = driver_fd;

  /* Init all endpoints */
  size_t i = 0;
  for (i = 0; i != 256; i++) {
    core_endpoints[i].id = (uint8_t)i;
    core_endpoints[i].state = SL_CPC_STATE_CLOSED;
    core_endpoints[i].ack = 0;
    core_endpoints[i].configured_tx_window_size = 1;
    core_endpoints[i].current_tx_window_space = 1;
    core_endpoints[i].re_transmit_timer_private_data = NULL;
    core_endpoints[i].on_uframe_data_reception = NULL;
  }

  /* Setup epoll */
  {
    /* Setup the driver socket */
    {
      static epoll_private_data_t private_data;

      private_data.callback = core_process_rx_driver;
      private_data.file_descriptor = driver_fd;
      private_data.endpoint_number = 0; /* Irrelevant here */

      epoll_register(&private_data);
    }
  }
}

void core_process_transmit_queue(void)
{
  /* Flush the transmit queue */
  while (transmit_queue != NULL) {
    if (!core_process_tx_queue()) {
      break;
    }
  }
}

cpc_endpoint_state_t core_get_endpoint_state(uint8_t ep_id)
{
  FATAL_ON(ep_id == 0);
  return core_endpoints[ep_id].state;
}

static void core_process_rx_driver(epoll_private_data_t *event_private_data)
{
  (void) event_private_data;
  frame_t *rx_frame;
  size_t frame_size;

  /* The driver unblocked, read the frame. Frames from the driver are complete */
  core_pull_frame_from_driver(&rx_frame, &frame_size);

  TRACE_CORE_RXD_FRAME(rx_frame, frame_size);

  /* Validate header checksum */
  {
    uint16_t hcs = hdlc_get_hcs(rx_frame->header);

    if (!sli_cpc_validate_crc_sw(rx_frame->header, SLI_CPC_HDLC_HEADER_SIZE, hcs)) {
      TRACE_CORE_INVALID_HEADER_CHECKSUM();
      free(rx_frame);
      return;
    }

    TRACE_CORE_RXD_VALID_FRAME();
  }

  uint16_t data_length = hdlc_get_length(rx_frame->header);
  uint8_t  address     = hdlc_get_address(rx_frame->header);
  uint8_t  control     = hdlc_get_control(rx_frame->header);
  uint8_t  type        = hdlc_get_frame_type(control);
  uint8_t  ack         = hdlc_get_ack(control);

  /* Make sure the length from the header matches the length reported by the driver*/
  BUG_ON(data_length != frame_size - SLI_CPC_HDLC_HEADER_RAW_SIZE);

  sl_cpc_endpoint_t* endpoint = find_endpoint(address);

  /* If endpoint is closed , reject the frame and return unless the frame itself is a reject, if so ignore it */
  if (endpoint->state != SL_CPC_STATE_OPEN) {
    if (type != SLI_CPC_HDLC_FRAME_TYPE_SUPERVISORY) {
      transmit_reject(NULL, address, 0, HDLC_REJECT_UNREACHABLE_ENDPOINT);
    }
    free(rx_frame);
    return;
  }

  /* For data and supervisory frames, send the ack right away */
  if (type == SLI_CPC_HDLC_FRAME_TYPE_INFORMATION || type == SLI_CPC_HDLC_FRAME_TYPE_SUPERVISORY) {
    process_ack(endpoint, ack);
  }

  switch (type) {
    case SLI_CPC_HDLC_FRAME_TYPE_INFORMATION:
      core_process_rx_i_frame(rx_frame);
      break;
    case SLI_CPC_HDLC_FRAME_TYPE_SUPERVISORY:
      core_process_rx_s_frame(rx_frame);
      break;
    case SLI_CPC_HDLC_FRAME_TYPE_UNNUMBERED:
      core_process_rx_u_frame(rx_frame);
      break;
    default:
      transmit_reject(endpoint, address, endpoint->ack, HDLC_REJECT_ERROR);
      TRACE_ENDPOINT_RXD_SUPERVISORY_DROPPED(endpoint);
      break;
  }

  /* core_pull_frame_from_driver() malloced rx_frame */
  free(rx_frame);
}

void core_process_endpoint_change(uint8_t endpoint_number, cpc_endpoint_state_t ep_state)
{
  if (ep_state == SL_CPC_STATE_OPEN) {
    if (core_endpoints[endpoint_number].state == SL_CPC_STATE_OPEN) {
      return; // Nothing to do
    }

    core_open_endpoint(endpoint_number,
                       0, /* No flags : iframe enables, uframe disabled*/
                       1);   /* tx window of 1*/
  } else {
    core_close_endpoint(endpoint_number, true);
  }
}

bool core_ep_is_busy(uint8_t ep_id)
{
  if (core_endpoints[ep_id].holding_list != NULL) {
    return true;
  }
  return false;
}

static void core_process_rx_i_frame(frame_t *rx_frame)
{
  sl_cpc_endpoint_t* endpoint;

  uint8_t address = hdlc_get_address(rx_frame->header);

  endpoint = &core_endpoints[hdlc_get_address(rx_frame->header)];

  TRACE_ENDPOINT_RXD_DATA_FRAME(endpoint);

  if (endpoint->id != 0 && (endpoint->state != SL_CPC_STATE_OPEN || server_listener_list_empty(endpoint->id))) {
    transmit_reject(endpoint, address, 0, HDLC_REJECT_UNREACHABLE_ENDPOINT);
    //TODO : goto endpoint_cleanup_check;
    return;
  }

  /* Prevent -2 on a zero length */
  BUG_ON(hdlc_get_length(rx_frame->header) < SLI_CPC_HDLC_FCS_SIZE);

  uint16_t rx_frame_payload_length = (uint16_t) (hdlc_get_length(rx_frame->header) - SLI_CPC_HDLC_FCS_SIZE);

  uint16_t fcs = hdlc_get_fcs(rx_frame->payload, rx_frame_payload_length);

  /* Validate payload checksum. In case it is invalid, NAK the packet. */
  if (!sli_cpc_validate_crc_sw(rx_frame->payload, rx_frame_payload_length, fcs)) {
    transmit_reject(endpoint, address, endpoint->ack, HDLC_REJECT_CHECKSUM_MISMATCH);
    //TODO : goto endpoint_cleanup_check;
    return;
  }

  uint8_t  control = hdlc_get_control(rx_frame->header);
  uint8_t  seq     = hdlc_get_seq(control);

  // data received, Push in Rx Queue and send Ack
  if (seq == endpoint->ack) {
    core_push_data_to_server(endpoint->id, rx_frame->payload, rx_frame_payload_length);

    TRACE_ENDPOINT_RXD_DATA_FRAME_QUEUED(endpoint);

#ifdef UNIT_TESTING
    cpc_unity_test_read_rx_callback(endpoint->id);
#endif

    // Update endpoint acknowledge number
    endpoint->ack++;
    endpoint->ack %= 8;

    // Send ack
    transmit_ack(endpoint);
  } else if (is_seq_valid(seq, endpoint->ack)) {
    // The packet was already received. We must re-send a ACK because the other side missed it the first time
    transmit_ack(endpoint);

    TRACE_ENDPOINT_RXD_DUPLICATE_DATA_FRAME(endpoint);
  } else {
    transmit_reject(endpoint, address, endpoint->ack, HDLC_REJECT_SEQUENCE_MISMATCH);
    //TODO : goto endpoint_cleanup_check;
    return;
  }
}

static void core_process_rx_s_frame(frame_t *rx_frame)
{
  sl_cpc_endpoint_t* endpoint;
  bool fatal_error = false;

  endpoint = find_endpoint(hdlc_get_address(rx_frame->header));

  TRACE_ENDPOINT_RXD_SUPERVISORY_FRAME(endpoint);

  cpc_endpoint_state_t new_state = endpoint->state;

  uint8_t supervisory_function = hdlc_get_supervisory_function(hdlc_get_control(rx_frame->header));

  uint16_t data_length = (hdlc_get_length(rx_frame->header) > 2) ? (uint16_t)(hdlc_get_length(rx_frame->header) - 2) : 0;

  switch (supervisory_function) {
    case SLI_CPC_HDLC_ACK_SUPERVISORY_FUNCTION:
      TRACE_ENDPOINT_RXD_SUPERVISORY_PROCESSED(endpoint);
      // ACK; already processed previously by receive_ack(), so nothing to do
      break;

    case SLI_CPC_HDLC_REJECT_SUPERVISORY_FUNCTION:

      TRACE_ENDPOINT_RXD_SUPERVISORY_PROCESSED(endpoint);
      BUG_ON(data_length != SLI_CPC_HDLC_REJECT_PAYLOAD_SIZE);

      switch (*((sl_cpc_reject_reason_t *)rx_frame->payload)) {
        case HDLC_REJECT_SEQUENCE_MISMATCH:
          fatal_error = true;
          new_state = SL_CPC_STATE_ERROR_FAULT;
          TRACE_ENDPOINT_RXD_REJECT_SEQ_MISMATCH(endpoint);
          break;

        case HDLC_REJECT_CHECKSUM_MISMATCH:
          if (endpoint->re_transmit_queue != NULL) {
            re_transmit_frame(endpoint);
          }
          TRACE_ENDPOINT_RXD_REJECT_CHECSUM_MISMATCH(endpoint);
          break;

        case HDLC_REJECT_OUT_OF_MEMORY:
          if (endpoint->re_transmit_queue != NULL) {
            re_transmit_frame(endpoint);
          }
          TRACE_ENDPOINT_RXD_REJECT_OUT_OF_MEMORY(endpoint);
          break;

        case HDLC_REJECT_SECURITY_ISSUE:
          fatal_error = true;
          new_state = SL_CPC_STATE_ERROR_SECURITY_INCIDENT;
          TRACE_ENDPOINT_RXD_REJECT_SECURITY_ISSUE(endpoint);
          break;

        case HDLC_REJECT_UNREACHABLE_ENDPOINT:
          fatal_error = true;
          new_state = SL_CPC_STATE_ERROR_DESTINATION_UNREACHABLE;
          TRACE_ENDPOINT_RXD_REJECT_DESTINATION_UNREACHABLE(endpoint);
          break;

        case HDLC_REJECT_ERROR:
        default:
          fatal_error = true;
          new_state = SL_CPC_STATE_ERROR_FAULT;
          TRACE_ENDPOINT_RXD_REJECT_FAULT(endpoint);
          break;
      }
      break;

    default:
      // Should not reach this case
      BUG();
      break;
  }

  if (fatal_error) {
    WARN("Fatal error %d, closing endoint #%d", endpoint->id, *((sl_cpc_reject_reason_t *)rx_frame->payload));
    server_close_endpoint(endpoint->id);
    server_expect_close(endpoint->id);
    core_close_endpoint(endpoint->id, false);
    endpoint->state = new_state;
  }
}

static void core_process_rx_u_frame(frame_t *rx_frame)
{
  uint16_t payload_length;
  uint8_t type;
  sl_cpc_endpoint_t *endpoint;

  // Retreive info from header
  {
    uint8_t address = hdlc_get_address(rx_frame->header);
    endpoint = find_endpoint(address);

    uint8_t control = hdlc_get_control(rx_frame->header);
    type = hdlc_get_unumbered_type(control);

    payload_length = hdlc_get_length(rx_frame->header);

    if (payload_length < 2) {
      payload_length = 0;
    } else {
      payload_length = (uint16_t)(payload_length - SLI_CPC_HDLC_FCS_SIZE);
    }
  }

  // Sanity checks
  {
    // Validate the payload checksum
    {
      uint16_t fcs = hdlc_get_fcs(rx_frame->payload, payload_length);

      if (!sli_cpc_validate_crc_sw(rx_frame->payload, payload_length, fcs)) {
        //TODO SLI_CPC_SYSVIEW_MARK_EVENT_ON_ENDPOINT(SLI_CPC_SYSVIEW_INVALID_FCS_EVENT, endpoint->id);
        TRACE_ENDPOINT_RXD_UNNUMBERED_DROPPED(endpoint, "Bad payload checksum");
        return;
      }
      TRACE_ENDPOINT_RXD_UNNUMBERED_FRAME(endpoint);
    }

    // Make sure U-Frames are enabled on this endpoint
    if (!(endpoint->flags & SL_CPC_OPEN_ENDPOINT_FLAG_UFRAME_ENABLE)) {
      TRACE_ENDPOINT_RXD_UNNUMBERED_DROPPED(endpoint, "U-Frame not enabled on endoint");
      return;
    }

    // If its an Information U-Frame, make sure they are enabled
    if ( (type == SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_INFORMATION)
         && (endpoint->flags & SL_CPC_OPEN_ENDPOINT_FLAG_UFRAME_INFORMATION_DISABLE)) {
      TRACE_ENDPOINT_RXD_UNNUMBERED_DROPPED(endpoint, "Information U-Frame not enabled on endpoint");
      return;
    }
  }

  switch (type) {
    case SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_INFORMATION:

      if (endpoint->on_uframe_data_reception != NULL) {
        endpoint->on_uframe_data_reception(endpoint->id, rx_frame->payload, payload_length);
      }
      break;

    case SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_POLL_FINAL:

      if (endpoint->poll_final.on_final != NULL) {
        endpoint->poll_final.on_final(endpoint->id, endpoint->poll_final.on_fnct_arg, rx_frame->payload, payload_length);
      }
      break;

    default:
      TRACE_ENDPOINT_RXD_UNNUMBERED_DROPPED(endpoint, "Information U-Frame not enabled on endpoint");
      return;
  }

  TRACE_ENDPOINT_RXD_UNNUMBERED_PROCESSED(endpoint);
}

/***************************************************************************//**
 * Write data from an endpoint
 ******************************************************************************/
void core_write(uint8_t endpoint_number, const void* message, size_t message_len, uint8_t flags)
{
  sl_cpc_endpoint_t* endpoint;
  sl_cpc_buffer_handle_t* buffer_handle;
  sl_cpc_transmit_queue_item_t * transmit_queue_item;
  bool iframe = true;
  uint8_t type = SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_UNKNOWN;

  FATAL_ON(message_len > UINT16_MAX);

  endpoint = find_endpoint(endpoint_number);

  /* Sanity checks */
  {
    /* Make sure the endpoint it opened */
    if (endpoint->state != SL_CPC_STATE_OPEN) {
      BUG();
      return;
    }

    /* if u-frame, make sure they are enabled */
    if ((flags & SL_CPC_FLAG_UNNUMBERED_INFORMATION)
        || (flags & SL_CPC_FLAG_UNNUMBERED_POLL)) {
      FATAL_ON(!(endpoint->flags & SL_CPC_OPEN_ENDPOINT_FLAG_UFRAME_ENABLE));

      iframe = false;

      if (flags & SL_CPC_FLAG_UNNUMBERED_INFORMATION) {
        type = SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_INFORMATION;
      } else if ((flags & SL_CPC_FLAG_UNNUMBERED_POLL)) {
        type = SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_POLL_FINAL;
      }
    }
    /* if I-frame, make sure they are not disabled */
    else {
      FATAL_ON(endpoint->flags & SL_CPC_OPEN_ENDPOINT_FLAG_IFRAME_DISABLE);
    }
  }

  /* Fill the buffer handle */
  {
    buffer_handle = (sl_cpc_buffer_handle_t*) calloc(1, sizeof(sl_cpc_buffer_handle_t));

    buffer_handle->data        = message;
    buffer_handle->data_length = (uint16_t)message_len;
    buffer_handle->endpoint    = endpoint;
    buffer_handle->address     = endpoint_number;

    if (iframe) {
      // Set the SEQ number and ACK number in the control byte
      buffer_handle->control = hdlc_create_control_data(endpoint->seq, endpoint->ack);
      // Update endpoint sequence number
      endpoint->seq++;
      endpoint->seq %= 8;
    } else {
      FATAL_ON(type == SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_UNKNOWN);
      buffer_handle->control = hdlc_create_control_unumbered(type);
    }

    /* Compute the payload's checksum  */
    {
      uint16_t fcs = sli_cpc_get_crc_sw(message, (uint16_t)message_len);

      buffer_handle->fcs[0] = (uint8_t)fcs;
      buffer_handle->fcs[1] = (uint8_t)(fcs >> 8);
    }
  }

  transmit_queue_item = (sl_cpc_transmit_queue_item_t*) malloc(sizeof(sl_cpc_transmit_queue_item_t));

  transmit_queue_item->handle = buffer_handle;

  // Deal with transmit window
  {
    // If U-Frame, skip the window and
    if (iframe == false) {
      sl_slist_push_back(&transmit_queue, &transmit_queue_item->node);
      core_process_transmit_queue();
    } else {
      if (endpoint->current_tx_window_space > 0) {
        endpoint->current_tx_window_space--;

        //Put frame in Tx Q so that it can be transmitted by CPC Core later
        sl_slist_push_back(&transmit_queue, &transmit_queue_item->node);
        core_process_transmit_queue();
      } else {
        //Put frame in endpoint holding list to wait for more space in the transmit window
        sl_slist_push_back(&endpoint->holding_list, &transmit_queue_item->node);
      }
    }
  }
}

void core_open_endpoint(uint8_t endpoint_number, uint8_t flags, uint8_t tx_window_size)
{
  sl_cpc_endpoint_t *ep;

  FATAL_ON(tx_window_size < TRANSMIT_WINDOW_MIN_SIZE);
  FATAL_ON(tx_window_size > TRANSMIT_WINDOW_MAX_SIZE);

  ep = &core_endpoints[endpoint_number];

  /* Check if endpoint was already opened */
  if (ep->state != SL_CPC_STATE_CLOSED) {
    BUG();
    return;
  }

  ep->id = endpoint_number;
  ep->flags = flags;
  ep->seq = 0;
  ep->ack = 0;
  ep->configured_tx_window_size = tx_window_size;
  ep->current_tx_window_space = ep->configured_tx_window_size;
  ep->frames_count_re_transmit_queue = 0;
  ep->state = SL_CPC_STATE_OPEN;

  int timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
  FATAL_SYSCALL_ON(timer_fd < 0);

  /* Setup epoll */
  {
    epoll_private_data_t* private_data = (epoll_private_data_t*) malloc(sizeof(epoll_private_data_t));

    ep->re_transmit_timer_private_data = private_data;

    private_data->callback = core_process_ep_timeout;
    private_data->file_descriptor = timer_fd;
    private_data->endpoint_number = endpoint_number;

    epoll_register(private_data);
  }

  sl_slist_init(&ep->re_transmit_queue);
  sl_slist_init(&ep->holding_list);

  TRACE_CORE_OPEN_ENDPOINT(ep);

  return;
}

/***************************************************************************//**
 * Close an endpoint
 ******************************************************************************/
sl_status_t core_close_endpoint(uint8_t endpoint_number, bool status_change)
{
  sl_cpc_endpoint_t *ep;
  sl_cpc_transmit_queue_item_t *item;

  ep = find_endpoint(endpoint_number);

  stop_re_transmit_timer(ep);

  item = SL_SLIST_ENTRY(ep->re_transmit_queue,
                        sl_cpc_transmit_queue_item_t,
                        node);

  while (item != NULL) {
    free(item->handle->hdlc_header);
    free((void *)item->handle->data);
    free(item->handle);

    /* Remove the item from the list*/
    sl_slist_remove(&ep->re_transmit_queue, &item->node);
    free(item);

    item = SL_SLIST_ENTRY(ep->re_transmit_queue,
                          sl_cpc_transmit_queue_item_t,
                          node);
  }

  item = SL_SLIST_ENTRY(ep->holding_list,
                        sl_cpc_transmit_queue_item_t,
                        node);

  while (item != NULL) {
    free(item->handle->hdlc_header);
    free((void *)item->handle->data);
    free(item->handle);

    /* Remove the item from the list*/
    sl_slist_remove(&ep->holding_list, &item->node);
    free(item);

    item = SL_SLIST_ENTRY(ep->holding_list,
                          sl_cpc_transmit_queue_item_t,
                          node);
  }

  item = SL_SLIST_ENTRY(transmit_queue,
                        sl_cpc_transmit_queue_item_t,
                        node);

  while (item != NULL) {
    if (item->handle->address == endpoint_number) {
      free(item->handle->hdlc_header);
      free((void *)item->handle->data);
      free(item->handle);

      sl_slist_remove(&transmit_queue, &item->node);
    }

    /* Remove the item from the list*/
    sl_slist_remove(&transmit_queue, &item->node);
    free(item);

    item = SL_SLIST_ENTRY(transmit_queue,
                          sl_cpc_transmit_queue_item_t,
                          node);
  }

  if (status_change) {
    ep->state = SL_CPC_STATE_CLOSED;
  }

  if (ep->re_transmit_timer_private_data != NULL) {
    epoll_unregister(ep->re_transmit_timer_private_data);

    close(((epoll_private_data_t *)ep->re_transmit_timer_private_data)->file_descriptor);
    free(ep->re_transmit_timer_private_data);

    ep->re_transmit_timer_private_data = NULL;
  }

  return SL_STATUS_OK;
}

void core_set_endpoint_option(uint8_t endpoint_number,
                              sl_cpc_endpoint_option_t option,
                              void *value)
{
  sl_cpc_endpoint_t *ep = &core_endpoints[endpoint_number];

  FATAL_ON(ep->state != SL_CPC_STATE_OPEN);

  switch (option) {
    case SL_CPC_ENDPOINT_ON_IFRAME_RECEIVE:
      //ep->on_iframe_data_reception = (sl_cpc_on_data_reception_t)value;
      break;
    case SL_CPC_ENDPOINT_ON_IFRAME_RECEIVE_ARG:
      //ep->on_iframe_data_reception_arg = value;
      break;
    case SL_CPC_ENDPOINT_ON_UFRAME_RECEIVE:
      ep->on_uframe_data_reception = (sl_cpc_on_data_reception_t)value;
      break;
    case SL_CPC_ENDPOINT_ON_UFRAME_RECEIVE_ARG:
      //ep->on_uframe_data_reception_arg = value;
      break;
    case SL_CPC_ENDPOINT_ON_IFRAME_WRITE_COMPLETED:
      //ep->on_iframe_write_completed = (sl_cpc_on_write_completed_t)value;
      break;
    case SL_CPC_ENDPOINT_ON_IFRAME_WRITE_COMPLETED_ARG:
      //ep->on_iframe_write_completed_arg = value;
      break;
    case SL_CPC_ENDPOINT_ON_UFRAME_WRITE_COMPLETED:
      //ep->on_uframe_write_completed = (sl_cpc_on_write_completed_t)value;
      break;
    case SL_CPC_ENDPOINT_ON_UFRAME_WRITE_COMPLETED_ARG:
      //ep->on_uframe_write_completed_arg = value;
      break;
    case SL_CPC_ENDPOINT_ON_FINAL:
      ep->poll_final.on_final = value;
      break;
    case SL_CPC_ENDPOINT_ON_POLL:
      //TODO cant happen on priamry
      break;
    case SL_CPC_ENDPOINT_ON_POLL_ARG:
    case SL_CPC_ENDPOINT_ON_FINAL_ARG:
      ep->poll_final.on_fnct_arg = value;
      break;
    default:
      FATAL("invalid option");
      break;
  }
}

/***************************************************************************//**
 * Process receive ACK frame
 ******************************************************************************/
static void process_ack(sl_cpc_endpoint_t *endpoint, uint8_t ack)
{
  sl_cpc_transmit_queue_item_t *item;
  sl_slist_node_t *item_node;
  sl_cpc_buffer_handle_t *frame;
  uint8_t control_byte;
  uint8_t seq_number;
  uint8_t ack_range_min;
  uint8_t ack_range_max;
  uint8_t frames_count_ack = 0;

  // Return if no frame to acknowledge
  if (endpoint->re_transmit_queue == NULL) {
    //BUG(); //?
    return;
  }

  // Get the sequence number of the first frame in the re-transmission queue
  item = SL_SLIST_ENTRY(endpoint->re_transmit_queue, sl_cpc_transmit_queue_item_t, node);
  frame = item->handle;

  control_byte = hdlc_get_control(frame->hdlc_header);
  seq_number = hdlc_get_seq(control_byte);

  // Calculate the acceptable ACK number range
  ack_range_min = (uint8_t)(seq_number + 1);
  ack_range_min %= 8;
  ack_range_max = (uint8_t)(seq_number + endpoint->frames_count_re_transmit_queue);
  ack_range_max %= 8;

  // Check that received ACK number is in range
  if (ack_range_max >= ack_range_min) {
    if (ack < ack_range_min
        || ack > ack_range_max) {
      // Invalid ack number
      return;
    }
  } else {
    if (ack > ack_range_max
        && ack < ack_range_min) {
      // Invalid ack number
      return;
    }
  }

  // Find number of frames acknowledged with ACK number
  if (ack > seq_number) {
    frames_count_ack = (uint8_t)(ack - seq_number);
  } else {
    frames_count_ack = (uint8_t)(8 - seq_number);
    frames_count_ack = (uint8_t)(frames_count_ack + ack);
  }

  // Reset re-transmit counter
  endpoint->packet_re_transmit_count = 0u;

  // Stop incomming re-transmit timeout
  stop_re_transmit_timer(endpoint);

  uint8_t i;
  // Remove all acknowledged frames in re-transmit queue
  for (i = 0; i < frames_count_ack; i++) {
    item_node = sl_slist_pop(&endpoint->re_transmit_queue);
    FATAL_ON(item_node == NULL);

    item = SL_SLIST_ENTRY(item_node, sl_cpc_transmit_queue_item_t, node);
    frame = item->handle;

#ifdef USE_ON_WRITE_COMPLETE
    on_write_completed(endpoint->id, SL_STATUS_OK);
#endif
    free((void *)frame->data);
    free(frame->hdlc_header);
    free(frame);
    free(item);

    // Update number of frames in re-transmit queue
    endpoint->frames_count_re_transmit_queue--;

    // Update transmit window
    endpoint->current_tx_window_space++;

    if (endpoint->re_transmit_queue == NULL) {
      break;
    }
  }

  // Put data frames hold in the endpoint in the tx queue if space in transmit window
  while (endpoint->holding_list != NULL && endpoint->current_tx_window_space > 0) {
    sl_slist_node_t *item = sl_slist_pop(&endpoint->holding_list);
    sl_slist_push_back(&transmit_queue, item);
    endpoint->current_tx_window_space--;
  }

  TRACE_ENDPOINT_RXD_ACK(endpoint);
}

/***************************************************************************//**
 * Transmit ACK frame
 ******************************************************************************/
static void transmit_ack(sl_cpc_endpoint_t *endpoint)
{
  sl_cpc_buffer_handle_t *handle;
  sl_cpc_transmit_queue_item_t *item;

  // Check if data frame are pending
  if (endpoint->holding_list != NULL) {
    // ACK will be piggyback so no need for ACK frame
    return;
  }

  // Get new frame handler
  handle = (sl_cpc_buffer_handle_t*) calloc(1, sizeof(sl_cpc_buffer_handle_t));
  FATAL_ON(handle == NULL);

  handle->endpoint = endpoint;
  handle->address = endpoint->id;

  // Set ACK number in the supervisory control byte
  handle->control = hdlc_create_control_supervisory(endpoint->ack, 0);

  // Put frame in Tx Q so that it can be transmitted by CPC Core later
  item = (sl_cpc_transmit_queue_item_t*) malloc(sizeof(sl_cpc_transmit_queue_item_t));
  FATAL_ON(item == NULL);

  item->handle = handle;

  sl_slist_push_back(&transmit_queue, &item->node);

  TRACE_ENDPOINT_TXD_ACK(endpoint);
}

/***************************************************************************//**
 * Re-transmit frame
 ******************************************************************************/
static void re_transmit_frame(sl_cpc_endpoint_t *endpoint)
{
  sl_cpc_transmit_queue_item_t *item;
  sl_slist_node_t *item_node;

  item_node = sl_slist_pop(&endpoint->re_transmit_queue);

  BUG_ON(item_node == NULL);

  item = SL_SLIST_ENTRY(item_node, sl_cpc_transmit_queue_item_t, node);

  // Free the previous header buffer. The tx queue process will malloc a new one and fill it.
  free(item->handle->hdlc_header);

  //Put frame in Tx Q so that it can be transmitted by CPC Core later
  sl_slist_push(&transmit_queue, &item->node);

  endpoint->packet_re_transmit_count++;
  endpoint->frames_count_re_transmit_queue--;

  // Signal task/process_action that frame is in Tx Queue

  TRACE_ENDPOINT_RETXD_DATA_FRAME(endpoint);

  return;
}

/***************************************************************************//**
 * Transmit REJECT frame
 ******************************************************************************/
static void transmit_reject(sl_cpc_endpoint_t *endpoint,
                            uint8_t address,
                            uint8_t ack,
                            sl_cpc_reject_reason_t reason)
{
  uint16_t fcs;
  sl_cpc_buffer_handle_t *handle;
  sl_cpc_transmit_queue_item_t *item;

  handle = (sl_cpc_buffer_handle_t*) calloc(1, sizeof(sl_cpc_buffer_handle_t));
  FATAL_ON(handle == NULL);

  handle->address = address;

  // Set the SEQ number and ACK number in the control byte
  handle->control = hdlc_create_control_supervisory(ack, SLI_CPC_HDLC_REJECT_SUPERVISORY_FUNCTION);

  handle->data = malloc(sizeof(uint8_t));
  FATAL_ON(handle == NULL);

  // Set in reason
  *((uint8_t *)handle->data) = (uint8_t)reason;
  handle->data_length = sizeof(uint8_t);

  // Compute payload CRC
  fcs = sli_cpc_get_crc_sw(handle->data, 1);
  handle->fcs[0] = (uint8_t)fcs;
  handle->fcs[1] = (uint8_t)(fcs >> 8);

  // Put frame in Tx Q so that it can be transmitted by CPC Core later
  item = (sl_cpc_transmit_queue_item_t*) malloc(sizeof(sl_cpc_transmit_queue_item_t));
  FATAL_ON(item == NULL);

  item->handle = handle;

  sl_slist_push_back(&transmit_queue, &item->node);

  if (endpoint != NULL) {
    switch (reason) {
      case HDLC_REJECT_CHECKSUM_MISMATCH:
        TRACE_ENDPOINT_TXD_REJECT_CHECKSUM_MISMATCH(endpoint);
        break;
      case HDLC_REJECT_SEQUENCE_MISMATCH:
        TRACE_ENDPOINT_TXD_REJECT_SEQ_MISMATCH(endpoint);
        break;
      case HDLC_REJECT_OUT_OF_MEMORY:
        TRACE_ENDPOINT_TXD_REJECT_OUT_OF_MEMORY(endpoint);
        break;
      case HDLC_REJECT_SECURITY_ISSUE:
        TRACE_ENDPOINT_TXD_REJECT_SECURITY_ISSUE(endpoint);
        break;
      case HDLC_REJECT_UNREACHABLE_ENDPOINT:
        TRACE_ENDPOINT_TXD_REJECT_DESTINATION_UNREACHABLE(endpoint);
        break;
      case HDLC_REJECT_ERROR:
      default:
        TRACE_ENDPOINT_TXD_REJECT_FAULT(endpoint);
        break;
    }
  } else {
    switch (reason) {
      case HDLC_REJECT_UNREACHABLE_ENDPOINT:
        TRACE_CORE_TXD_REJECT_DESTINATION_UNREACHABLE();
        break;
      default:
        FATAL();
        break;
    }
  }
}

/***************************************************************************//**
 * Transmit the next data frame queued in a endpoint's transmit queue.
 ******************************************************************************/
static bool core_process_tx_queue(void)
{
  sl_slist_node_t *node;
  sl_cpc_transmit_queue_item_t *item;
  sl_cpc_buffer_handle_t *frame;
  uint16_t data_length;
  uint8_t frame_type;

  // Return if nothing to transmit
  if (transmit_queue == NULL) {
    WARN("Called core_process_tx_queue with an empty tx queue");
    return false;
  }

  // Get first queued frame for transmission
  node = sl_slist_pop(&transmit_queue);
  item = SL_SLIST_ENTRY(node, sl_cpc_transmit_queue_item_t, node);
  frame = item->handle;

  frame->hdlc_header = malloc(SLI_CPC_HDLC_HEADER_RAW_SIZE);
  FATAL_ON(frame->hdlc_header == NULL);

  // Form the HDLC header
  data_length = (frame->data_length != 0) ? (uint16_t)(frame->data_length + 2) : 0;

  frame_type = hdlc_get_frame_type(frame->control);

  if (frame_type == SLI_CPC_HDLC_FRAME_TYPE_INFORMATION) {
    hdlc_set_control_ack(&frame->control, frame->endpoint->ack);
  }

  hdlc_create_header(frame->hdlc_header, frame->address, data_length, frame->control, true);

  /* Construct and send the frame to the driver */
  {
    const size_t frame_length = SLI_CPC_HDLC_HEADER_RAW_SIZE + data_length; //the +2 for fcs is in 'data_length'

    frame_t* frame_buffer = (frame_t*) malloc(frame_length);

    memcpy(frame_buffer->header, frame->hdlc_header, SLI_CPC_HDLC_HEADER_RAW_SIZE);

    memcpy(frame_buffer->payload, frame->data, frame->data_length);

    if (data_length != 0) {
      memcpy(&frame_buffer->payload[frame->data_length], frame->fcs, sizeof(frame->fcs));
    }

    core_push_frame_to_driver(frame_buffer, frame_length);

    free(frame_buffer);
  }

  TRACE_ENDPOINT_FRAME_TRANSMIT_SUBMITTED(frame->endpoint);

  switch (frame_type) {
    // Put frame in in re-transmission queue if it's a I-frame type (with data)
    case SLI_CPC_HDLC_FRAME_TYPE_INFORMATION:
      sl_slist_push_back(&frame->endpoint->re_transmit_queue, &item->node);
      frame->endpoint->frames_count_re_transmit_queue++;
      start_re_transmit_timer(frame->endpoint);
      break;

    // In case of s-frame, free all resources, inclusind the data field because it is the core who
    // manages s-frame resources.
    case SLI_CPC_HDLC_FRAME_TYPE_SUPERVISORY:
      free(item);
      free(frame->hdlc_header);
      if (frame->data_length != 0) {
        free((void*)frame->data);
      }
      free(frame);
      break;

    // In case of unnumbered, all buffers can be freed since the core don't deal with retransmits
    // The frame->data though, isn't freed because it's the u-frame user who manages it.
    case SLI_CPC_HDLC_FRAME_TYPE_UNNUMBERED:
      free(item);
      free(frame->hdlc_header);
      free(frame);
      break;

    default:
      FATAL();
      break;
  }

  return true;
}

/***************************************************************************//**
 * Callback for re-transmit frame
 ******************************************************************************/
static void re_transmit_timeout(sl_cpc_endpoint_t* endpoint)
{
  if (endpoint->packet_re_transmit_count >= SLI_CPC_RE_TRANSMIT) {
    WARN("Retransmit limit reached, closing endoint #%d", endpoint->id);
    server_close_endpoint(endpoint->id);
    core_close_endpoint(endpoint->id, true);
    endpoint->state = SL_CPC_STATE_ERROR_DESTINATION_UNREACHABLE;
  } else {
    re_transmit_frame(endpoint);
  }
}

/***************************************************************************//**
 * Check if seq equal ack minus one
 ******************************************************************************/
static bool is_seq_valid(uint8_t seq, uint8_t ack)
{
  bool result = false;

  if (seq == (ack - 1u)) {
    result = true;
  } else if (ack == 0u && seq == 7u) {
    result = true;
  }

  return result;
}

/***************************************************************************//**
 * Returns a pointer to the endpoint struct for a given endpoint_number
 ******************************************************************************/
static sl_cpc_endpoint_t* find_endpoint(uint8_t endpoint_number)
{
  return &core_endpoints[endpoint_number];
}

/***************************************************************************//**
 * Returns a pointer to the endpoint struct for a given endpoint_number
 ******************************************************************************/
//FIXME : for debug purpose, to be completed
void core_reset_endpoint_sequence(uint8_t endpoint_number)
{
  sl_cpc_endpoint_t *ep;

  ep = &core_endpoints[endpoint_number];

  while (ep->state != SL_CPC_STATE_CLOSED) {
    usleep(1000);
  }

  // Cannot reset an open endpoint
  FATAL_ON(ep->state != SL_CPC_STATE_CLOSED);

  ep->id = endpoint_number;
  ep->seq = 0;
  ep->ack = 0;
  ep->frames_count_re_transmit_queue = 0;
  ep->packet_re_transmit_count = 0;
  ep->current_tx_window_space = ep->configured_tx_window_size;
}

/***************************************************************************//**
 * Stops the re-transmit timer for a given endpoint
 ******************************************************************************/
static void stop_re_transmit_timer(sl_cpc_endpoint_t* endpoint)
{
  int ret;
  epoll_private_data_t* fd_timer_private_data;

  /* Passing itimerspec with it_value of 0 stops the timer. */
  const struct itimerspec cancel_time = { .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
                                          .it_value    = { .tv_sec = 0, .tv_nsec = 0 } };

  fd_timer_private_data = endpoint->re_transmit_timer_private_data;

  if (fd_timer_private_data == NULL) {
    return;
  }

  ret = timerfd_settime(fd_timer_private_data->file_descriptor,
                        0,
                        &cancel_time,
                        NULL);

  FATAL_SYSCALL_ON(ret < 0);
}

/***************************************************************************//**
 * Start the re-transmit timer for a given endpoint
 ******************************************************************************/
static void start_re_transmit_timer(sl_cpc_endpoint_t* endpoint)
{
  int ret;
  epoll_private_data_t* fd_timer_private_data;

  fd_timer_private_data = endpoint->re_transmit_timer_private_data;

  /* Make sure the timer file descriptor is open*/
  FATAL_ON(fd_timer_private_data == NULL);
  FATAL_ON(fd_timer_private_data->file_descriptor < 0);

  /* fires every 2 second */
  const struct itimerspec timeout_time = { .it_interval = { .tv_sec = 2, .tv_nsec = 0 },
                                           .it_value    = { .tv_sec = 2, .tv_nsec = 0 } };

  ret = timerfd_settime(fd_timer_private_data->file_descriptor,
                        0,
                        &timeout_time,
                        NULL);

  FATAL_SYSCALL_ON(ret < 0);
}

/***************************************************************************//**
 * Loops through all the endpoints and if its timer has elapsed, perform a re-transmit
 ******************************************************************************/
static void core_process_ep_timeout(epoll_private_data_t *event_private_data)
{
  int fd_timer = event_private_data->file_descriptor;
  uint8_t endpoint_number = event_private_data->endpoint_number;

  /* Ack the timer */
  {
    uint64_t expiration;
    ssize_t ret;

    ret = read(fd_timer, &expiration, sizeof(expiration));
    FATAL_ON(ret < 0);

    /* we missed a timeout*/
    TRACE_CORE("Retransmit expiration = %lld", expiration);
    WARN_ON(expiration != 1);
  }

  re_transmit_timeout(&core_endpoints[endpoint_number]);
}

/***************************************************************************//**
 * Pushes a complete frame to the driver.
 *
 *
 ******************************************************************************/
static void core_push_frame_to_driver(const void *frame, size_t frame_len)
{
  ssize_t ret = send(driver_sock_fd, frame, frame_len, 0);

  FATAL_SYSCALL_ON(ret < 0);

  FATAL_ON((size_t) ret != frame_len);
}

/***************************************************************************//**
 * Fetches the next frame from the driver.
 *
 * The buffer for the retrieved frame is dynamically allocated inside this
 * function and passed to the caller. It is the caller's job to free the buffer
 * when done with it.
 ******************************************************************************/
static void core_pull_frame_from_driver(frame_t** frame_buf, size_t* frame_buf_len)
{
  int datagram_length;

  /* Poll the socket to get the next pending datagram size */
  {
    int retval = ioctl(driver_sock_fd, FIONREAD, &datagram_length);

    FATAL_SYSCALL_ON(retval < 0);

    /* The socket had no data. This function is intended to be called
     * when we know the socket has data. */
    BUG_ON(datagram_length == 0);

    /* The length of the frame should be at minimum a header length */
    BUG_ON((size_t)datagram_length < sizeof(frame_t));
  }

  /* Allocate a buffer of the right size */
  {
    *frame_buf = (frame_t*) malloc((size_t)datagram_length);

    FATAL_ON(*frame_buf == NULL);
  }

  /* Fetch the datagram from the driver socket */
  {
    ssize_t ret =  recv(driver_sock_fd, *frame_buf, (size_t)datagram_length, 0);

    FATAL_SYSCALL_ON(ret < 0);

    /* The next pending datagram size should be equal to what we just read */
    FATAL_ON((size_t)ret != (size_t)datagram_length);
  }

  *frame_buf_len = (size_t)datagram_length;
}

/***************************************************************************//**
 * Sends a data payload to the server
 *
 * When a payload is processed by the core and ready to be sent to it's endpoint
 * socket, the core calls this function with the endpoint id. This function
 * allocated momentarily a buffer to store the payload and metainformation to
 * communicate with the server, sends this buffer and then frees it.
 ******************************************************************************/
static void core_push_data_to_server(uint8_t ep_id, const void *data, size_t data_len)
{
  server_push_data_to_endpoint(ep_id, data, data_len);
}
