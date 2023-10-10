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

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/time.h>
#include <inttypes.h>

#include "cpcd/config.h"
#include "cpcd/exchange.h"
#include "cpcd/logging.h"
#include "cpcd/security.h"
#include "cpcd/sleep.h"
#include "cpcd/sl_slist.h"
#include "cpcd/sl_status.h"
#include "cpcd/utils.h"
#include "cpcd/server_core.h"

#include "server_core/server/server.h"
#include "server_core/epoll/epoll.h"
#include "server_core/system_endpoint/system.h"
#include "server_core/core/core.h"
#include "server_core/core/hdlc.h"
#include "server_core/core/crc.h"

#if defined(UNIT_TESTING)
#include "driver/driver_emul.h"
#include "test/unity/cpc_unity_common.h"
#endif

#if defined(UNIT_TESTING)
#define USE_ON_WRITE_COMPLETE
#endif

#if !defined(SLI_CPC_SECURITY_NONCE_FRAME_COUNTER_RESET_VALUE)
#define SLI_CPC_SECURITY_NONCE_FRAME_COUNTER_RESET_VALUE 0
#endif

#define ABS(a)  ((a) < 0 ? -(a) : (a))
#define X_ENUM_TO_STR(x) #x
#define ENUM_TO_STR(x) X_ENUM_TO_STR(x)

/*******************************************************************************
 ***************************  GLOBAL VARIABLES   *******************************
 ******************************************************************************/
core_debug_counters_t primary_core_debug_counters;
core_debug_counters_t secondary_core_debug_counters;

/*******************************************************************************
 ***************************  LOCAL DECLARATIONS   *****************************
 ******************************************************************************/

/*******************************************************************************
 ***************************  LOCAL VARIABLES   ********************************
 ******************************************************************************/

static epoll_private_data_t driver_sock_private_data;
static epoll_private_data_t driver_sock_notify_private_data;
static int                  stats_timer_fd;
static sl_cpc_endpoint_t    core_endpoints[SL_CPC_ENDPOINT_MAX_COUNT];
static sl_slist_node_t      *transmit_queue = NULL;
static sl_slist_node_t      *pending_on_security_ready_queue = NULL;
static sl_slist_node_t      *pending_on_tx_complete = NULL;

#if defined(ENABLE_ENCRYPTION)
static bool security_session_last_packet_acked = false;
#endif

/*******************************************************************************
 **************************   LOCAL FUNCTIONS   ********************************
 ******************************************************************************/

static void release_buffer_handle(sl_cpc_buffer_handle_t *frame);
static void push_back_buffer_handle(sl_slist_node_t **head, sl_cpc_buffer_handle_t *frame);
static sl_cpc_buffer_handle_t* pop_buffer_handle(sl_slist_node_t **head);

static void core_process_rx_driver_notification(epoll_private_data_t *event_private_data);
static void core_process_rx_driver(epoll_private_data_t *event_private_data);
static void core_process_ep_timeout(epoll_private_data_t *event_private_data);

static void core_process_rx_i_frame(frame_t *rx_frame);
static void core_process_rx_s_frame(frame_t *rx_frame);
static void core_process_rx_u_frame(frame_t *rx_frame);

/* CPC core functions  */
static bool core_process_tx_queue(void);
static void core_clear_transmit_queue(sl_slist_node_t **head, int endpoint_id);
static void process_ack(sl_cpc_endpoint_t *endpoint, uint8_t ack);
static void transmit_ack(sl_cpc_endpoint_t *endpoint);
static void re_transmit_frame(sl_cpc_endpoint_t *endpoint);
static bool is_seq_valid(uint8_t seq, uint8_t ack);
static sl_cpc_endpoint_t* find_endpoint(uint8_t endpoint_number);
static void transmit_reject(sl_cpc_endpoint_t *endpoint, uint8_t address, uint8_t ack, sl_cpc_reject_reason_t reason);

/* Functions to operate on linux fd timers */
static void stop_re_transmit_timer(sl_cpc_endpoint_t* endpoint);
static void start_re_transmit_timer(sl_cpc_endpoint_t* endpoint, struct timespec offset);

/* Functions to communicate with the driver and server */
static void core_push_frame_to_driver(const void *frame, size_t frame_len);
static bool core_pull_frame_from_driver(frame_t** frame_buf, size_t* frame_buf_len);

static sl_status_t core_push_data_to_server(uint8_t ep_id, const void *data, size_t data_len);

static bool security_is_ready(void);
static bool should_encrypt_frame(sl_cpc_buffer_handle_t *frame);
#if defined(ENABLE_ENCRYPTION)
static bool should_decrypt_frame(sl_cpc_endpoint_t *endpoint, uint16_t payload_len);
static void core_on_security_state_change(sl_cpc_security_state_t old, sl_cpc_security_state_t new);
#endif
static void core_fetch_secondary_debug_counters(epoll_private_data_t *event_private_data);

/*******************************************************************************
 **************************   IMPLEMENTATION    ********************************
 ******************************************************************************/
cpc_endpoint_state_t core_state_mapper(uint8_t state)
{
  #define SL_CPC_STATE_FREED 6 // State freed, internal to Secondary

  switch (state) {
    case SL_CPC_STATE_OPEN:
    case SL_CPC_STATE_CLOSED:
    case SL_CPC_STATE_CLOSING:
    case SL_CPC_STATE_ERROR_DESTINATION_UNREACHABLE:
    case SL_CPC_STATE_ERROR_SECURITY_INCIDENT:
    case SL_CPC_STATE_ERROR_FAULT:
      return state;
    case SL_CPC_STATE_FREED:
      return SL_CPC_STATE_CLOSED;
    default:
      BUG("A new state (%d) has been added to the Secondary that has no equivalent on the daemon.", state);
  }
}

const char* core_stringify_state(cpc_endpoint_state_t state)
{
  switch (state) {
    case SL_CPC_STATE_OPEN:
      return ENUM_TO_STR(SL_CPC_STATE_OPEN);
    case SL_CPC_STATE_CLOSED:
      return ENUM_TO_STR(SL_CPC_STATE_CLOSED);
    case SL_CPC_STATE_CLOSING:
      return ENUM_TO_STR(SL_CPC_STATE_CLOSING);
    case SL_CPC_STATE_ERROR_DESTINATION_UNREACHABLE:
      return ENUM_TO_STR(SL_CPC_STATE_ERROR_DESTINATION_UNREACHABLE);
    case SL_CPC_STATE_ERROR_SECURITY_INCIDENT:
      return ENUM_TO_STR(SL_CPC_STATE_ERROR_SECURITY_INCIDENT);
    case SL_CPC_STATE_ERROR_FAULT:
      return ENUM_TO_STR(SL_CPC_STATE_ERROR_FAULT);
    default:
      BUG("A new state (%d) has been added to the Secondary that has no equivalent on the daemon.", state);
  }
}

static void on_connect_notification(sl_cpc_system_command_handle_t *handle,
                                    sl_cpc_property_id_t property_id,
                                    void* property_value,
                                    size_t property_length,
                                    sl_status_t status)
{
  (void)handle;
  (void)property_length;
  (void)property_value;

  uint8_t ep_id = PROPERTY_ID_TO_EP_ID(property_id);

  switch (status) {
    case SL_STATUS_IN_PROGRESS:
    case SL_STATUS_OK:
      TRACE_CORE("Connection notification confirmation received for ep#%d", ep_id);
      break;

    case SL_STATUS_TIMEOUT:
    case SL_STATUS_ABORT:
      WARN("Failed to receive connection notification confirmation for ep#%d", ep_id);
      break;
    default:
      FATAL("Unknown status %d on_connect_notification", status);
      break;
  }
}

static void on_disconnect_notification(sl_cpc_system_command_handle_t *handle,
                                       sl_cpc_property_id_t property_id,
                                       void* property_value,
                                       size_t property_length,
                                       sl_status_t status)
{
  (void)handle;
  (void)property_length;
  (void)property_value;

  uint8_t ep_id = PROPERTY_ID_TO_EP_ID(property_id);
  BUG_ON(core_endpoints[ep_id].state == SL_CPC_STATE_OPEN);

  switch (status) {
    case SL_STATUS_IN_PROGRESS:
    case SL_STATUS_OK:
      TRACE_CORE("Disconnection notification received for ep#%d", ep_id);
      core_set_endpoint_state(ep_id, SL_CPC_STATE_CLOSED);
      break;

    case SL_STATUS_TIMEOUT:
    case SL_STATUS_ABORT:
      core_set_endpoint_in_error(ep_id, SL_CPC_STATE_ERROR_DESTINATION_UNREACHABLE);
      WARN("Failed to receive disconnection notification for ep#%d", ep_id);
      break;
    default:
      FATAL("Unknown status %d during disconnection notification", status);
      break;
  }
}

static void core_compute_re_transmit_timeout(sl_cpc_endpoint_t *endpoint)
{
  // Implemented using Karn’s algorithm
  // Based off of RFC 2988 Computing TCP's Retransmission Timer
  static bool first_rtt_measurement = true;
  struct timespec current_time;
  int64_t current_timestamp_ms;
  int64_t previous_timestamp_ms;
  uint32_t round_trip_time_ms = 0;
  uint32_t rto = 0;

  const uint8_t k = 4; // This value is recommended by the Karn’s algorithm

  FATAL_ON(endpoint == NULL);

  clock_gettime(CLOCK_MONOTONIC, &current_time);

  current_timestamp_ms = (int64_t)(current_time.tv_sec) * 1000 + (int64_t)(current_time.tv_nsec / 1000000);
  previous_timestamp_ms = (int64_t)(endpoint->last_iframe_sent_timestamp.tv_sec) * 1000 + (int64_t)(endpoint->last_iframe_sent_timestamp.tv_nsec / 1000000);

  if (previous_timestamp_ms == 0) {
    // Deal with the very unlikely scenario where the ACK is received before the tx_complete is executed
    // Set the round trip time to a reasonable value
    round_trip_time_ms = 1;
  } else {
    if (current_timestamp_ms < previous_timestamp_ms) {
      round_trip_time_ms = 1;
    } else {
      int64_t tmp_rtt_ms = (current_timestamp_ms - previous_timestamp_ms);
      FATAL_ON(tmp_rtt_ms < 0);
      if (tmp_rtt_ms > SLI_CPC_MAX_ROUND_TRIP_TIME_MS) {
        tmp_rtt_ms = SLI_CPC_MAX_ROUND_TRIP_TIME_MS;
      }
      round_trip_time_ms = (uint32_t) tmp_rtt_ms;
    }
  }

  TRACE_CORE("RTT on ep %d is %" PRIu32 "ms", endpoint->id, round_trip_time_ms);

  if (first_rtt_measurement) {
    endpoint->smoothed_rtt = round_trip_time_ms;
    endpoint->rtt_variation = round_trip_time_ms / 2;
    first_rtt_measurement = false;
  } else {
    // RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'| where beta is 0.25
    endpoint->rtt_variation = 3 * (endpoint->rtt_variation / 4) +  (uint32_t) ABS((int32_t)endpoint->smoothed_rtt - (int32_t)round_trip_time_ms) / 4;

    // SRTT <- (1 - alpha) * SRTT + alpha * R' where alpha is 0.125
    endpoint->smoothed_rtt = 7 * (endpoint->smoothed_rtt / 8) + round_trip_time_ms / 8;
  }

  // Impose a lower bound on the variation, we don't want the RTO to converge too close to the RTT
  if (endpoint->rtt_variation < SL_CPC_MIN_RE_TRANSMIT_TIMEOUT_MINIMUM_VARIATION_MS) {
    endpoint->rtt_variation = SL_CPC_MIN_RE_TRANSMIT_TIMEOUT_MINIMUM_VARIATION_MS;
  }

  rto = endpoint->smoothed_rtt + k * endpoint->rtt_variation;

  if (rto <= 0) {
    WARN("There was an issue during the re_transmit_timeout calculation for \
          endpoint #(%" PRIu8 "), RTO(%" PRIu32 ") <= 0, smoothed_rtt = %" PRIu32 ", rtt_variation = %" PRIu32 "",
         endpoint->id, rto, endpoint->smoothed_rtt, endpoint->rtt_variation);
    rto = SL_CPC_MIN_RE_TRANSMIT_TIMEOUT_MS;
  }

  if (rto > SL_CPC_MAX_RE_TRANSMIT_TIMEOUT_MS) {
    rto = SL_CPC_MAX_RE_TRANSMIT_TIMEOUT_MS;
  } else if (rto < SL_CPC_MIN_RE_TRANSMIT_TIMEOUT_MS) {
    rto = SL_CPC_MIN_RE_TRANSMIT_TIMEOUT_MS;
  }

  endpoint->re_transmit_timeout_ms = rto;
  TRACE_CORE("RTO on ep %" PRIu8 " is calculated to %" PRIu32 "ms", endpoint->id, endpoint->re_transmit_timeout_ms);
}

#if defined(ENABLE_ENCRYPTION)
static void core_on_security_state_change(sl_cpc_security_state_t old, sl_cpc_security_state_t new)
{
  TRACE_CORE("Security changed state: %d -> %d", (int)old, (int)new);
  if (old == SECURITY_STATE_INITIALIZING
      && new == SECURITY_STATE_INITIALIZED) {
    core_endpoints[SL_CPC_ENDPOINT_SYSTEM].encrypted = true;
  } else if (old == SECURITY_STATE_RESETTING
             && new == SECURITY_STATE_INITIALIZED) {
    for (size_t i = 0; i < SL_CPC_ENDPOINT_MAX_COUNT; i++) {
      core_endpoints[i].frame_counter_tx = SLI_CPC_SECURITY_NONCE_FRAME_COUNTER_RESET_VALUE;
      core_endpoints[i].frame_counter_rx = SLI_CPC_SECURITY_NONCE_FRAME_COUNTER_RESET_VALUE;
#if defined(UNIT_TESTING)
      sli_cpc_drv_emul_set_frame_counter(i, SLI_CPC_SECURITY_NONCE_FRAME_COUNTER_RESET_VALUE, true);
      sli_cpc_drv_emul_set_frame_counter(i, SLI_CPC_SECURITY_NONCE_FRAME_COUNTER_RESET_VALUE, false);
#endif
    }
  } else if (new == SECURITY_STATE_INITIALIZING) {
    core_endpoints[SL_CPC_ENDPOINT_SYSTEM].encrypted = false;
  }
}
#endif

void core_init(int driver_fd, int driver_notify_fd)
{
  /* Init all endpoints */
  size_t i = 0;
  for (i = 0; i < SL_CPC_ENDPOINT_MAX_COUNT; i++) {
    core_endpoints[i].id = (uint8_t)i;
    core_endpoints[i].state = SL_CPC_STATE_CLOSED;
    core_endpoints[i].ack = 0;
    core_endpoints[i].configured_tx_window_size = 1;
    core_endpoints[i].current_tx_window_space = 1;
    core_endpoints[i].re_transmit_timer_private_data = NULL;
    core_endpoints[i].on_uframe_data_reception = NULL;
    core_endpoints[i].on_iframe_data_reception = NULL;
    core_endpoints[i].last_iframe_sent_timestamp = (struct timespec){ 0 };
    core_endpoints[i].smoothed_rtt = 0;
    core_endpoints[i].rtt_variation = 0;
    core_endpoints[i].re_transmit_timeout_ms = SL_CPC_MAX_RE_TRANSMIT_TIMEOUT_MS;
#if defined(ENABLE_ENCRYPTION)
    core_endpoints[i].encrypted = false;
    core_endpoints[i].frame_counter_tx = 0;
    core_endpoints[i].frame_counter_rx = 0;
#endif
  }

#if defined(ENABLE_ENCRYPTION)
  security_register_state_change_callback(core_on_security_state_change);
#endif

  /* Setup epoll */
  {
    /* Setup the driver data socket */
    {
      driver_sock_private_data.callback = core_process_rx_driver;
      driver_sock_private_data.file_descriptor = driver_fd;
      driver_sock_private_data.endpoint_number = 0; /* Irrelevant here */

      epoll_register(&driver_sock_private_data);
    }

    /* Setup the driver notification socket */
    {
      driver_sock_notify_private_data.callback = core_process_rx_driver_notification;
      driver_sock_notify_private_data.file_descriptor = driver_notify_fd;
      driver_sock_notify_private_data.endpoint_number = 0; /* Irrelevant here */

      epoll_register(&driver_sock_notify_private_data);
    }
  }

  /* Setup timer to fetch secondary debug counter */
  if (config.stats_interval > 0) {
    stats_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    FATAL_SYSCALL_ON(stats_timer_fd < 0);

    struct itimerspec timeout_time = { .it_interval = { .tv_sec = config.stats_interval, .tv_nsec = 0 },
                                       .it_value    = { .tv_sec = config.stats_interval, .tv_nsec = 0 } };

    int ret = timerfd_settime(stats_timer_fd,
                              0,
                              &timeout_time,
                              NULL);

    FATAL_SYSCALL_ON(ret < 0);

    /* Setup epoll */
    {
      epoll_private_data_t* private_data = (epoll_private_data_t*) zalloc(sizeof(epoll_private_data_t));
      FATAL_SYSCALL_ON(private_data == NULL);

      private_data->callback = core_fetch_secondary_debug_counters;
      private_data->file_descriptor = stats_timer_fd;

      epoll_register(private_data);
    }
  }

  sl_slist_init(&pending_on_tx_complete);
}

void core_process_transmit_queue(void)
{
  /* Flush the transmit queue */
  while (transmit_queue != NULL || pending_on_security_ready_queue != NULL) {
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

void core_set_endpoint_state(uint8_t ep_id, cpc_endpoint_state_t state)
{
  if (core_endpoints[ep_id].state != state) {
    TRACE_CORE("Changing ep#%d state from %s to %s", ep_id, core_stringify_state(core_endpoints[ep_id].state), core_stringify_state(state));
    core_endpoints[ep_id].state = state;
    server_on_endpoint_state_change(ep_id, state);
  }
}

bool core_get_endpoint_encryption(uint8_t ep_id)
{
#if defined(ENABLE_ENCRYPTION)
  return core_endpoints[ep_id].encrypted;
#else
  (void) ep_id;
  return false;
#endif
}

static void core_update_secondary_debug_counter(sl_cpc_system_command_handle_t *handle,
                                                sl_cpc_property_id_t property_id,
                                                void* property_value,
                                                size_t property_length,
                                                sl_status_t status)
{
  (void)handle;

  if (status == SL_STATUS_TIMEOUT) {
    WARN("Secondary counters query timed out");
    return;
  } else if (status == SL_STATUS_ABORT) {
    WARN("Secondary counters query aborted");
    return;
  }

  if (status != SL_STATUS_OK && status != SL_STATUS_IN_PROGRESS) {
    BUG();
  }

  if (property_id == PROP_LAST_STATUS) {
    FATAL("Secondary does not handle the DEBUG_COUNTERS property, please update secondary or disable print-stats");
  }

  FATAL_ON(property_id != PROP_CORE_DEBUG_COUNTERS);
  FATAL_ON(property_value == NULL || property_length > sizeof(core_debug_counters_t));

  memcpy(&secondary_core_debug_counters, property_value, property_length);
}

static void core_fetch_secondary_debug_counters(epoll_private_data_t *event_private_data)
{
  int fd_timer = event_private_data->file_descriptor;

  /* Ack the timer */
  {
    uint64_t expiration;
    ssize_t ret;

    ret = read(fd_timer, &expiration, sizeof(expiration));
    FATAL_ON(ret < 0);
  }

  sl_cpc_system_cmd_property_get(core_update_secondary_debug_counter,
                                 PROP_CORE_DEBUG_COUNTERS, 0, 0, false);
}

static void core_process_rx_driver_notification(epoll_private_data_t *event_private_data)
{
  sl_cpc_buffer_handle_t *frame;
  uint8_t frame_type;

  (void)event_private_data;

  struct timespec tx_complete_timestamp;

  BUG_ON(driver_sock_notify_private_data.file_descriptor < 1);
  ssize_t ret = recv(driver_sock_notify_private_data.file_descriptor,
                     &tx_complete_timestamp,
                     sizeof(tx_complete_timestamp),
                     MSG_DONTWAIT);

  /* Socket closed */
  if (ret == 0 || (ret < 0 && errno == ECONNRESET)) {
    TRACE_CORE("Driver closed the notification socket");
    epoll_unregister(&driver_sock_notify_private_data);
    int ret_close = close(driver_sock_notify_private_data.file_descriptor);
    FATAL_SYSCALL_ON(ret_close != 0);
    driver_sock_notify_private_data.file_descriptor = -1;
    return;
  }

  FATAL_SYSCALL_ON(ret < 0);

  frame = pop_buffer_handle(&pending_on_tx_complete);
  frame_type = hdlc_get_frame_type(frame->control);

  if (frame_type == SLI_CPC_HDLC_FRAME_TYPE_INFORMATION) {
    if (frame->endpoint->state == SL_CPC_STATE_OPEN) {
      // Remember when we sent this i-frame in order to calculate round trip time
      // Only do so if this is not a re_transmit
      if (frame->re_transmit_count == 0u) {
        frame->endpoint->last_iframe_sent_timestamp = tx_complete_timestamp;
      }

      if (frame->endpoint->re_transmit_queue != NULL) {
        start_re_transmit_timer(frame->endpoint, tx_complete_timestamp);
      }
    }
  }

  release_buffer_handle(frame);
}

static void core_process_rx_driver(epoll_private_data_t *event_private_data)
{
  (void)event_private_data;
  frame_t *rx_frame;
  size_t frame_size;

  /* The driver unblocked, read the frame. Frames from the driver are complete */
  if (core_pull_frame_from_driver(&rx_frame, &frame_size) == false) {
    return;
  }

  TRACE_CORE_RXD_FRAME(rx_frame, frame_size);

  /* Validate header checksum */
  {
    uint16_t hcs = hdlc_get_hcs(rx_frame->header);

    if (!sli_cpc_validate_crc_sw(rx_frame->header, SLI_CPC_HDLC_HEADER_SIZE, hcs)) {
      TRACE_CORE_INVALID_HEADER_CHECKSUM();
      free(rx_frame);
      return;
    }
  }

  uint16_t data_length = hdlc_get_length(rx_frame->header);
  uint8_t  address     = hdlc_get_address(rx_frame->header);
  uint8_t  control     = hdlc_get_control(rx_frame->header);
  uint8_t  type        = hdlc_get_frame_type(control);
  uint8_t  ack         = hdlc_get_ack(control);

  /* Make sure the length from the header matches the length reported by the driver*/
  BUG_ON(data_length != frame_size - SLI_CPC_HDLC_HEADER_RAW_SIZE);

  sl_cpc_endpoint_t* endpoint = find_endpoint(address);

  if (type != SLI_CPC_HDLC_FRAME_TYPE_UNNUMBERED) {
    if (config.operation_mode == MODE_NORMAL && !server_core_reset_is_received_reset_reason()) {
      // Secondary not yet reset, discard packet
      const char* frame_type_str = (type == SLI_CPC_HDLC_FRAME_TYPE_INFORMATION) ? "i" : "s";
      TRACE_CORE("Received %s-frame before secondary had reset.", frame_type_str);
      TRACE_ENDPOINT_RXD_DATA_FRAME_DROPPED(endpoint);
      free(rx_frame);
      return;
    }
  }

  /* If endpoint is closed , reject the frame and return unless the frame itself is a reject, if so ignore it */
  if (endpoint->state != SL_CPC_STATE_OPEN) {
    if (type != SLI_CPC_HDLC_FRAME_TYPE_SUPERVISORY) {
      transmit_reject(NULL, address, 0, HDLC_REJECT_UNREACHABLE_ENDPOINT);
    }
    free(rx_frame);
    return;
  }

  /* For data and supervisory frames, process the ack right away */
  if (type == SLI_CPC_HDLC_FRAME_TYPE_INFORMATION || type == SLI_CPC_HDLC_FRAME_TYPE_SUPERVISORY) {
    process_ack(endpoint, ack);
  }

  switch (type) {
    case SLI_CPC_HDLC_FRAME_TYPE_INFORMATION:
      core_process_rx_i_frame(rx_frame);
      TRACE_CORE_RXD_VALID_IFRAME();
      break;
    case SLI_CPC_HDLC_FRAME_TYPE_SUPERVISORY:
      core_process_rx_s_frame(rx_frame);
      TRACE_CORE_RXD_VALID_SFRAME();
      break;
    case SLI_CPC_HDLC_FRAME_TYPE_UNNUMBERED:
      core_process_rx_u_frame(rx_frame);
      TRACE_CORE_RXD_VALID_UFRAME();
      break;
    default:
      transmit_reject(endpoint, address, endpoint->ack, HDLC_REJECT_ERROR);
      TRACE_ENDPOINT_RXD_SUPERVISORY_DROPPED(endpoint);
      break;
  }

  /* core_pull_frame_from_driver() malloced rx_frame */
  free(rx_frame);
}

bool core_ep_is_closing(uint8_t ep_id)
{
  return core_endpoints[ep_id].state == SL_CPC_STATE_CLOSING;
}

void core_process_endpoint_change(uint8_t endpoint_number, cpc_endpoint_state_t ep_state, bool encryption, uint8_t tx_window_size)
{
  if (ep_state == SL_CPC_STATE_OPEN) {
    if (core_endpoints[endpoint_number].state == SL_CPC_STATE_OPEN) {
      return; // Nothing to do
    }

    core_open_endpoint(endpoint_number,
                       0,              /* No flags : iframe enables, uframe disabled*/
                       tx_window_size, /* tx window, should be between 1 and 7 */
                       encryption);    /* encryption of the underlying endpoint */
  } else {
    core_close_endpoint(endpoint_number, true, false);
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
#if defined(ENABLE_ENCRYPTION)
  bool frame_was_decrypted = false;
#endif

  uint8_t address = hdlc_get_address(rx_frame->header);

  endpoint = &core_endpoints[hdlc_get_address(rx_frame->header)];

  TRACE_ENDPOINT_RXD_DATA_FRAME(endpoint);

  if (endpoint->id != 0 && (endpoint->state != SL_CPC_STATE_OPEN || server_listener_list_empty(endpoint->id))) {
    transmit_reject(endpoint, address, 0, HDLC_REJECT_UNREACHABLE_ENDPOINT);
    return;
  }

  /* Prevent -2 on a zero length */
  BUG_ON(hdlc_get_length(rx_frame->header) < SLI_CPC_HDLC_FCS_SIZE);

  uint16_t rx_frame_payload_length = (uint16_t) (hdlc_get_length(rx_frame->header) - SLI_CPC_HDLC_FCS_SIZE);

  uint16_t fcs = hdlc_get_fcs(rx_frame->payload, rx_frame_payload_length);

  /* Validate payload checksum. In case it is invalid, NAK the packet. */
  if (!sli_cpc_validate_crc_sw(rx_frame->payload, rx_frame_payload_length, fcs)) {
    transmit_reject(endpoint, address, endpoint->ack, HDLC_REJECT_CHECKSUM_MISMATCH);
    TRACE_CORE_INVALID_PAYLOAD_CHECKSUM();
    return;
  }

  uint8_t  control = hdlc_get_control(rx_frame->header);
  uint8_t  seq     = hdlc_get_seq(control);

  // data received, Push in Rx Queue and send Ack
  if (seq == endpoint->ack) {
#if defined(ENABLE_ENCRYPTION)
    if (should_decrypt_frame(endpoint, rx_frame_payload_length)) {
      uint16_t tag_len = (uint16_t)security_encrypt_get_extra_buffer_size();
      uint8_t *output;
      sl_status_t status;

      /* the payload buffer must be longer than the security tag */
      BUG_ON(rx_frame_payload_length < tag_len);
      rx_frame_payload_length = (uint16_t)(rx_frame_payload_length - tag_len);

      output = zalloc(rx_frame_payload_length);
      FATAL_ON(output == NULL);

      // set the ack to 0 when computing security tag
      uint8_t ack = hdlc_get_ack(control);
      hdlc_set_control_ack(&rx_frame->header[SLI_CPC_HDLC_CONTROL_POS], 0);

      status = security_decrypt(endpoint,
                                rx_frame->header, SLI_CPC_HDLC_HEADER_SIZE,
                                rx_frame->payload, rx_frame_payload_length,
                                output,
                                &(rx_frame->payload[rx_frame_payload_length]), tag_len);

      // restore ack
      hdlc_set_control_ack(&rx_frame->header[SLI_CPC_HDLC_CONTROL_POS], ack);

      if (status != SL_STATUS_OK) {
        WARN("Failed to decrypt frame, status=0x%x", status);
        free(output);
        transmit_reject(endpoint, address, endpoint->ack, HDLC_REJECT_SECURITY_ISSUE);
        return;
      }

      frame_was_decrypted = true;
      memcpy(&rx_frame->payload[0], output, rx_frame_payload_length);
      free(output);
    }
#endif

    // Check if the received message is a final reply for the system endpoint
    if (hdlc_is_poll_final(control)) {
      BUG_ON(endpoint->id != 0); // Only system endpoint can receive final messages
      BUG_ON(endpoint->poll_final.on_final == NULL); // Received final, but no callback assigned
      endpoint->poll_final.on_final(endpoint->id, (void *)SLI_CPC_HDLC_FRAME_TYPE_INFORMATION, rx_frame->payload, rx_frame_payload_length);
    } else {
      if (endpoint->id == SL_CPC_ENDPOINT_SYSTEM) {
        // unsolicited i-frame
        if (endpoint->on_iframe_data_reception != NULL) {
          endpoint->on_iframe_data_reception(endpoint->id, rx_frame->payload, rx_frame_payload_length);
        }
      } else {
        sl_status_t status = core_push_data_to_server(endpoint->id,
                                                      rx_frame->payload,
                                                      rx_frame_payload_length);
        if (status == SL_STATUS_FAIL) {
          // can't recover from that, close endpoint
          core_close_endpoint(endpoint->id, true, false);
          return;
        } else if (status == SL_STATUS_WOULD_BLOCK) {
#if defined(ENABLE_ENCRYPTION)
          if (frame_was_decrypted) {
            security_xfer_rollback(endpoint);
          }
#endif
          transmit_reject(endpoint, address, endpoint->ack, HDLC_REJECT_OUT_OF_MEMORY);
          return;
        }
      }
    }

    TRACE_ENDPOINT_RXD_DATA_FRAME_QUEUED(endpoint);

#ifdef UNIT_TESTING
    if (endpoint->id != SL_CPC_ENDPOINT_SYSTEM && endpoint->id != SL_CPC_ENDPOINT_SECURITY) {
      cpc_unity_test_read_rx_callback(endpoint->id);
    }
#endif

    // Update endpoint acknowledge number
    endpoint->ack++;
    endpoint->ack %= 8;

    // Send ack
    transmit_ack(endpoint);
  } else if (is_seq_valid(seq, endpoint->ack)) {
    // The packet was already received. We must re-send a ACK because the other side missed it the first time
    TRACE_ENDPOINT_RXD_DUPLICATE_DATA_FRAME(endpoint);
    transmit_ack(endpoint);
  } else {
    transmit_reject(endpoint, address, endpoint->ack, HDLC_REJECT_SEQUENCE_MISMATCH);
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
          TRACE_ENDPOINT_RXD_REJECT_SEQ_MISMATCH(endpoint);
          WARN("Sequence mismatch on endpoint #%d", endpoint->id);
          break;

        case HDLC_REJECT_CHECKSUM_MISMATCH:
          if (endpoint->re_transmit_queue != NULL) {
            re_transmit_frame(endpoint);
          }
          TRACE_ENDPOINT_RXD_REJECT_CHECKSUM_MISMATCH(endpoint);
          WARN("Remote received a packet with an invalid checksum");
          break;

        case HDLC_REJECT_OUT_OF_MEMORY:
          TRACE_ENDPOINT_RXD_REJECT_OUT_OF_MEMORY(endpoint);
          break;

        case HDLC_REJECT_SECURITY_ISSUE:
          fatal_error = true;
          new_state = SL_CPC_STATE_ERROR_SECURITY_INCIDENT;
          TRACE_ENDPOINT_RXD_REJECT_SECURITY_ISSUE(endpoint);
          WARN("Security issue on endpoint #%d", endpoint->id);
          break;

        case HDLC_REJECT_UNREACHABLE_ENDPOINT:
          fatal_error = true;
          new_state = SL_CPC_STATE_ERROR_DESTINATION_UNREACHABLE;
          TRACE_ENDPOINT_RXD_REJECT_DESTINATION_UNREACHABLE(endpoint);
          WARN("Unreachable endpoint #%d", endpoint->id);
          break;

        case HDLC_REJECT_ERROR:
        default:
          fatal_error = true;
          new_state = SL_CPC_STATE_ERROR_FAULT;
          TRACE_ENDPOINT_RXD_REJECT_FAULT(endpoint);
          WARN("Endpoint #%d fault", endpoint->id);
          break;
      }
      break;

    default:
      BUG("Illegal switch");
      break;
  }

  if (fatal_error) {
    WARN("Fatal error %d, endoint #%d is in error.", *((sl_cpc_reject_reason_t *)rx_frame->payload), endpoint->id);
    core_set_endpoint_in_error(endpoint->id, new_state);
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
    TRACE_ENDPOINT_RXD_UNNUMBERED_FRAME(endpoint);

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
    if (payload_length > 0) {
      uint16_t fcs = hdlc_get_fcs(rx_frame->payload, payload_length);

      if (!sli_cpc_validate_crc_sw(rx_frame->payload, payload_length, fcs)) {
        TRACE_CORE_INVALID_PAYLOAD_CHECKSUM();
        TRACE_ENDPOINT_RXD_UNNUMBERED_DROPPED(endpoint, "Bad payload checksum");
        return;
      }
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
      if (endpoint->id != SL_CPC_ENDPOINT_SYSTEM) {
        FATAL("Received an unnumbered final frame but it was not addressed to the system enpoint");
      } else if (endpoint->poll_final.on_final != NULL) {
        endpoint->poll_final.on_final(endpoint->id, (void *)SLI_CPC_HDLC_FRAME_TYPE_UNNUMBERED, rx_frame->payload, payload_length);
      } else {
        BUG();
      }
      break;

    case SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_ACKNOWLEDGE:
      BUG_ON(endpoint->id != SL_CPC_ENDPOINT_SYSTEM);
      sl_cpc_system_on_unnumbered_acknowledgement();
      break;

    default:
      TRACE_ENDPOINT_RXD_UNNUMBERED_DROPPED(endpoint, "U-Frame not enabled on endpoint");
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
  bool iframe = true;
  bool poll = (flags & SL_CPC_FLAG_INFORMATION_POLL) ? true : false;
  uint8_t type = SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_UNKNOWN;
  void* payload = NULL;

  FATAL_ON(message_len > UINT16_MAX);

  endpoint = find_endpoint(endpoint_number);

  /* Sanity checks */
  {
    /* Make sure the endpoint it opened */
    if (endpoint->state != SL_CPC_STATE_OPEN) {
      WARN("Tried to write on closed endpoint #%d", endpoint_number);
      return;
    }

    /* if u-frame, make sure they are enabled */
    if ((flags & SL_CPC_FLAG_UNNUMBERED_INFORMATION) || (flags & SL_CPC_FLAG_UNNUMBERED_RESET_COMMAND) || (flags & SL_CPC_FLAG_UNNUMBERED_POLL)) {
      FATAL_ON(!(endpoint->flags & SL_CPC_OPEN_ENDPOINT_FLAG_UFRAME_ENABLE));

      iframe = false;

      if (flags & SL_CPC_FLAG_UNNUMBERED_INFORMATION) {
        type = SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_INFORMATION;
      } else if (flags & SL_CPC_FLAG_UNNUMBERED_RESET_COMMAND) {
        type = SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_RESET_SEQ;
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
    buffer_handle = (sl_cpc_buffer_handle_t*) zalloc(sizeof(sl_cpc_buffer_handle_t));
    FATAL_SYSCALL_ON(buffer_handle == NULL);

    payload = zalloc(message_len);
    FATAL_SYSCALL_ON(payload == NULL);
    memcpy(payload, message, message_len);

    buffer_handle->data                = payload;
    buffer_handle->data_length         = (uint16_t)message_len;
    buffer_handle->endpoint            = endpoint;
    buffer_handle->address             = endpoint_number;
    buffer_handle->ref_cnt             = 0;

    if (iframe) {
      // Set the SEQ number and ACK number in the control byte
      buffer_handle->control = hdlc_create_control_data(endpoint->seq, endpoint->ack, poll);
      // Update endpoint sequence number
      endpoint->seq++;
      endpoint->seq %= 8;
      TRACE_CORE("Sequence # is now %d on ep %d", endpoint->seq, endpoint->id);
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

  // Deal with transmit window
  {
    // If U-Frame, skip the window and send immediately
    if (iframe == false) {
      push_back_buffer_handle(&transmit_queue, buffer_handle);
      core_process_transmit_queue();
    } else {
      if (endpoint->current_tx_window_space > 0) {
        push_back_buffer_handle(&endpoint->re_transmit_queue, buffer_handle);
        endpoint->frames_count_re_transmit_queue++;
        endpoint->current_tx_window_space--;

        // Put frame in Tx Q so that it can be transmitted by CPC Core later
        push_back_buffer_handle(&transmit_queue, buffer_handle);
        core_process_transmit_queue();
      } else {
        // Put frame in endpoint holding list to wait for more space in the transmit window
        push_back_buffer_handle(&endpoint->holding_list, buffer_handle);
      }
    }
  }
}

void core_open_endpoint(uint8_t endpoint_number, uint8_t flags, uint8_t tx_window_size, bool encryption)
{
  sl_cpc_endpoint_t *ep;
  cpc_endpoint_state_t previous_state;

  FATAL_ON(tx_window_size < TRANSMIT_WINDOW_MIN_SIZE);
  FATAL_ON(tx_window_size > TRANSMIT_WINDOW_MAX_SIZE);

  ep = &core_endpoints[endpoint_number];

  /* Check if endpoint was already opened */
  if (ep->state != SL_CPC_STATE_CLOSED) {
    BUG("Endpoint already opened");
    return;
  }

  /* Keep the previous state to log the transition */
  previous_state = ep->state;
  memset(ep, 0x00, sizeof(sl_cpc_endpoint_t));
  ep->state = previous_state;
  core_set_endpoint_state(endpoint_number, SL_CPC_STATE_OPEN);

  ep->id = endpoint_number;
  ep->flags = flags;
  ep->configured_tx_window_size = tx_window_size;
  ep->current_tx_window_space = ep->configured_tx_window_size;
  ep->re_transmit_timeout_ms = SL_CPC_MAX_RE_TRANSMIT_TIMEOUT_MS;
#if defined(ENABLE_ENCRYPTION)
  ep->encrypted = encryption;
  ep->frame_counter_tx = SLI_CPC_SECURITY_NONCE_FRAME_COUNTER_RESET_VALUE;
  ep->frame_counter_rx = SLI_CPC_SECURITY_NONCE_FRAME_COUNTER_RESET_VALUE;
#else
  (void)encryption;
#endif

  int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
  FATAL_SYSCALL_ON(timer_fd < 0);

  /* Setup epoll */
  {
    epoll_private_data_t* private_data = (epoll_private_data_t*) zalloc(sizeof(epoll_private_data_t));
    FATAL_SYSCALL_ON(private_data == NULL);

    ep->re_transmit_timer_private_data = private_data;

    private_data->callback = core_process_ep_timeout;
    private_data->file_descriptor = timer_fd;
    private_data->endpoint_number = endpoint_number;

    epoll_register(private_data);
  }

  sl_slist_init(&ep->re_transmit_queue);
  sl_slist_init(&ep->holding_list);

  TRACE_CORE_OPEN_ENDPOINT(ep->id);

  if (endpoint_number != SL_CPC_ENDPOINT_SYSTEM
      && endpoint_number != SL_CPC_ENDPOINT_SECURITY) {
    // Notify the secondary that the endpoint was opened
    sl_cpc_system_cmd_property_set(on_connect_notification,
                                   0, /* unlimited retries */
                                   100000, /* 100ms between retries*/
                                   EP_ID_TO_PROPERTY_STATE(ep->id),
                                   &ep->state,
                                   sizeof(cpc_endpoint_state_t),
                                   false);
  }

  return;
}

/***************************************************************************//**
 * Set an endpoint in error
 ******************************************************************************/
void core_set_endpoint_in_error(uint8_t endpoint_number, cpc_endpoint_state_t new_state)
{
  if (endpoint_number == 0) {
    WARN("System endpoint in error, new state: %s. Restarting it.", core_stringify_state(new_state));
    sl_cpc_system_request_sequence_reset();
  } else {
    WARN("Setting ep#%d in error, new state: %s", endpoint_number, core_stringify_state(new_state));

    server_close_endpoint(endpoint_number, true);
    core_close_endpoint(endpoint_number, false, false);
    core_set_endpoint_state(endpoint_number, new_state);
  }
}

/***************************************************************************//**
 * Reset the sequence and ack on a specified endpoint
 ******************************************************************************/
void core_reset_endpoint_sequence(uint8_t endpoint_number)
{
  core_endpoints[endpoint_number].seq = 0;
  core_endpoints[endpoint_number].ack = 0;
}

static void core_clear_transmit_queue(sl_slist_node_t **head, int endpoint_id)
{
  sl_slist_node_t *current_node;
  sl_slist_node_t *next_node;
  bool filter_with_endpoint_id;
  uint8_t ep_id;

  if (!*head) {
    return;
  }

  if (endpoint_id < 0) {
    filter_with_endpoint_id = false;
  } else {
    filter_with_endpoint_id = true;
    ep_id = (uint8_t)endpoint_id;
  }

  // init current_node to the first element in the list
  current_node = *head;

  while (current_node) {
    // store next_node right away as the element containing
    // current_node might get free'd below
    next_node = current_node->node;

    sl_cpc_transmit_queue_item_t *item = SL_SLIST_ENTRY(current_node, sl_cpc_transmit_queue_item_t, node);
    if (!filter_with_endpoint_id
        || (filter_with_endpoint_id && item->handle->address == ep_id)) {
      item->handle->ref_cnt--;
      release_buffer_handle(item->handle);

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
 * Close an endpoint
 ******************************************************************************/
sl_status_t core_close_endpoint(uint8_t endpoint_number, bool notify_secondary, bool force_close)
{
  sl_cpc_endpoint_t *ep;

  ep = find_endpoint(endpoint_number);

  BUG_ON(ep->state == SL_CPC_STATE_CLOSED);

  TRACE_CORE("Closing endpoint #%d", endpoint_number);

  stop_re_transmit_timer(ep);

  core_clear_transmit_queue(&ep->re_transmit_queue, -1);
  core_clear_transmit_queue(&ep->holding_list, -1);
  core_clear_transmit_queue(&transmit_queue, endpoint_number);
  core_clear_transmit_queue(&pending_on_security_ready_queue, endpoint_number);

  if (notify_secondary && endpoint_number != SL_CPC_ENDPOINT_SECURITY) {
    // State will be set to closed when secondary closes its endpoint
    core_set_endpoint_state(ep->id, SL_CPC_STATE_CLOSING);

    // Notify the secondary that the endpoint should get closed
    sl_cpc_system_cmd_property_set(on_disconnect_notification,
                                   5,      /* 5 retries */
                                   100000, /* 100ms between retries*/
                                   EP_ID_TO_PROPERTY_STATE(ep->id),
                                   &ep->state,
                                   sizeof(cpc_endpoint_state_t),
                                   false);
  }

  if (ep->re_transmit_timer_private_data != NULL) {
    epoll_unregister(ep->re_transmit_timer_private_data);

    close(((epoll_private_data_t *)ep->re_transmit_timer_private_data)->file_descriptor);
    free(ep->re_transmit_timer_private_data);

    ep->re_transmit_timer_private_data = NULL;
  }

  if (force_close) {
    core_set_endpoint_state(ep->id, SL_CPC_STATE_CLOSED);
    TRACE_CORE_CLOSE_ENDPOINT(ep->id);
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
      ep->on_iframe_data_reception = (sl_cpc_on_data_reception_t)value;
      break;
    case SL_CPC_ENDPOINT_ON_IFRAME_RECEIVE_ARG:
      BUG("invalid option");
      break;
    case SL_CPC_ENDPOINT_ON_UFRAME_RECEIVE:
      ep->on_uframe_data_reception = (sl_cpc_on_data_reception_t)value;
      break;
    case SL_CPC_ENDPOINT_ON_UFRAME_RECEIVE_ARG:
      BUG("invalid option");
      break;
    case SL_CPC_ENDPOINT_ON_IFRAME_WRITE_COMPLETED:
      BUG("invalid option");
      break;
    case SL_CPC_ENDPOINT_ON_IFRAME_WRITE_COMPLETED_ARG:
      BUG("invalid option");
      break;
    case SL_CPC_ENDPOINT_ON_UFRAME_WRITE_COMPLETED:
      BUG("invalid option");
      break;
    case SL_CPC_ENDPOINT_ON_UFRAME_WRITE_COMPLETED_ARG:
      BUG("invalid option");
      break;
    case SL_CPC_ENDPOINT_ON_FINAL:
      ep->poll_final.on_final = value;
      break;
    case SL_CPC_ENDPOINT_ON_POLL:
      // Can't happen on the primary
      BUG("invalid option");
      break;
    case SL_CPC_ENDPOINT_ON_POLL_ARG:
    case SL_CPC_ENDPOINT_ON_FINAL_ARG:
      ep->poll_final.on_fnct_arg = value;
      break;
    default:
      BUG("invalid option");
      break;
  }
}

/***************************************************************************//**
 * Process receive ACK frame
 ******************************************************************************/
static void process_ack(sl_cpc_endpoint_t *endpoint, uint8_t ack)
{
  sl_cpc_transmit_queue_item_t *item;
  sl_cpc_buffer_handle_t *frame;
  uint8_t frames_count_ack = 0;
  uint8_t ack_range_min;
  uint8_t ack_range_max;
  uint8_t control_byte;
  uint8_t seq_number;

  // Return if no frame to acknowledge
  if (endpoint->re_transmit_queue == NULL) {
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

  // Stop incoming re-transmit timeout
  stop_re_transmit_timer(endpoint);

  TRACE_CORE("%d Received ack %d seq number %d", endpoint->id, ack, seq_number);
  core_compute_re_transmit_timeout(endpoint);

  // Remove all acknowledged frames in re-transmit queue
  for (uint8_t i = 0; i < frames_count_ack; i++) {
    frame = pop_buffer_handle(&endpoint->re_transmit_queue);
    BUG_ON(frame == NULL);

    control_byte = hdlc_get_control(frame->hdlc_header);

    BUG_ON(hdlc_get_frame_type(frame->control) != SLI_CPC_HDLC_FRAME_TYPE_INFORMATION);

#ifdef USE_ON_WRITE_COMPLETE
    on_write_completed(endpoint->id, SL_STATUS_OK);
#endif

    if (endpoint->id == SL_CPC_ENDPOINT_SYSTEM && hdlc_is_poll_final(control_byte)) {
      sl_cpc_system_cmd_poll_acknowledged(frame->data);
    }

#if defined(ENABLE_ENCRYPTION)
    if (frame->security_session_last_packet) {
      security_session_last_packet_acked = true;
    }
#endif

    release_buffer_handle(frame);

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
    sl_cpc_transmit_queue_item_t *item;
    sl_slist_node_t *node;

    // Move item from the holding list to the retransmit queue
    node = sl_slist_pop(&endpoint->holding_list);
    item = SL_SLIST_ENTRY(node, sl_cpc_transmit_queue_item_t, node);

    sl_slist_push_back(&endpoint->re_transmit_queue, &item->node);
    endpoint->frames_count_re_transmit_queue++;
    endpoint->current_tx_window_space--;

    // add the handle to the transmit queue
    push_back_buffer_handle(&transmit_queue, item->handle);

    epoll_watch_back(endpoint->id);
  }

  TRACE_ENDPOINT_RXD_ACK(endpoint, ack);
}

/***************************************************************************//**
 * Transmit ACK frame
 ******************************************************************************/
static void transmit_ack(sl_cpc_endpoint_t *endpoint)
{
  sl_cpc_buffer_handle_t *handle;

  // Get new frame handler
  handle = (sl_cpc_buffer_handle_t*) zalloc(sizeof(sl_cpc_buffer_handle_t));
  FATAL_SYSCALL_ON(handle == NULL);

  handle->endpoint = endpoint;
  handle->address = endpoint->id;

  // Set ACK number in the supervisory control byte
  handle->control = hdlc_create_control_supervisory(endpoint->ack, SLI_CPC_HDLC_ACK_SUPERVISORY_FUNCTION);

  push_back_buffer_handle(&transmit_queue, handle);
  TRACE_CORE("Endpoint #%d sent ACK: %d", endpoint->id, endpoint->ack);

  core_process_transmit_queue();

  TRACE_ENDPOINT_TXD_ACK(endpoint);
}

/***************************************************************************//**
 * Re-transmit frame
 ******************************************************************************/
static void re_transmit_frame(sl_cpc_endpoint_t *endpoint)
{
  sl_cpc_transmit_queue_item_t *item;
  sl_cpc_buffer_handle_t *frame;
  sl_slist_node_t *item_node;

  item_node = endpoint->re_transmit_queue;
  BUG_ON(item_node == NULL);

  item = SL_SLIST_ENTRY(item_node, sl_cpc_transmit_queue_item_t, node);
  frame = item->handle;

  // Don't re_transmit the frame if it is already being transmitted
  if (frame->ref_cnt > 1) {
    return;
  }

  // Only i-frames support retransmission
  BUG_ON(hdlc_get_frame_type(item->handle->control) != SLI_CPC_HDLC_FRAME_TYPE_INFORMATION);

  // Free the previous header buffer. The tx queue process will malloc a new one and fill it.
  free(item->handle->hdlc_header);

  frame->re_transmit_count++;

  // Put frame in Tx Q so that it can be transmitted by CPC Core later
  push_back_buffer_handle(&transmit_queue, frame);

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

  handle = (sl_cpc_buffer_handle_t*) zalloc(sizeof(sl_cpc_buffer_handle_t));
  FATAL_ON(handle == NULL);

  handle->address = address;

  // Set the SEQ number and ACK number in the control byte
  handle->control = hdlc_create_control_supervisory(ack, SLI_CPC_HDLC_REJECT_SUPERVISORY_FUNCTION);

  handle->data = zalloc(sizeof(uint8_t));
  FATAL_SYSCALL_ON(handle->data == NULL);

  // Set in reason
  *((uint8_t *)handle->data) = (uint8_t)reason;
  handle->data_length = sizeof(uint8_t);

  // Compute payload CRC
  fcs = sli_cpc_get_crc_sw(handle->data, 1);
  handle->fcs[0] = (uint8_t)fcs;
  handle->fcs[1] = (uint8_t)(fcs >> 8);

  push_back_buffer_handle(&transmit_queue, handle);

  if (endpoint != NULL) {
    switch (reason) {
      case HDLC_REJECT_CHECKSUM_MISMATCH:
        TRACE_ENDPOINT_TXD_REJECT_CHECKSUM_MISMATCH(endpoint);
        WARN("Host received a packet with an invalid checksum on ep %d", endpoint->id);
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

static void push_back_buffer_handle(sl_slist_node_t **head, sl_cpc_buffer_handle_t *frame)
{
  sl_cpc_transmit_queue_item_t *item;

  item = (sl_cpc_transmit_queue_item_t*) zalloc(sizeof(sl_cpc_transmit_queue_item_t));
  FATAL_SYSCALL_ON(item == NULL);

  frame->ref_cnt++;
  item->handle = frame;

  sl_slist_push_back(head, &item->node);
}

static sl_cpc_buffer_handle_t* pop_buffer_handle(sl_slist_node_t **head)
{
  sl_cpc_transmit_queue_item_t *item;
  sl_cpc_buffer_handle_t *frame;
  sl_slist_node_t *node;

  // Get first queued item
  node = sl_slist_pop(head);
  item = SL_SLIST_ENTRY(node, sl_cpc_transmit_queue_item_t, node);
  FATAL_ON(item == NULL);

  frame = item->handle;
  frame->ref_cnt--;

  free(item);

  return frame;
}

static void release_buffer_handle(sl_cpc_buffer_handle_t *frame)
{
  if (frame->ref_cnt == 0) {
#if defined(ENABLE_ENCRYPTION)
    if (frame->security_info) {
      free((void *)frame->security_info);
    }
#endif

    if (frame->data_length != 0) {
      free((void *)frame->data);
    }

    free(frame->hdlc_header);
    free(frame);
  }
}

/***************************************************************************//**
 * Transmit the next data frame queued in a endpoint's transmit queue.
 ******************************************************************************/
static bool core_process_tx_queue(void)
{
  sl_cpc_transmit_queue_item_t *item;
  sl_cpc_buffer_handle_t *frame;
  sl_slist_node_t *node;
  uint16_t total_length;
  uint8_t frame_type;

  // If the security is setup, prioritize sending packets that were hold back
  // in pending_on_security_ready_queue.
  // If the queue is empty, or if the security is not ready, process packets
  // from the regular transmit queue. Later down this function, it will be
  // determined if the packet can be sent or if it must be hold back.
  if (pending_on_security_ready_queue != NULL && security_is_ready()) {
    TRACE_CORE("Sending packet that were hold back because security was not ready");
    node = sl_slist_pop(&pending_on_security_ready_queue);
  } else {
    // Return if nothing to transmit
    if (transmit_queue == NULL) {
      TRACE_CORE("transmit_queue is empty and core is not ready yet to process hold back packets");
      return false;
    }

    // Get first queued frame for transmission
    node = sl_slist_pop(&transmit_queue);
  }

  item = SL_SLIST_ENTRY(node, sl_cpc_transmit_queue_item_t, node);
  frame = item->handle;

  frame->hdlc_header = zalloc(SLI_CPC_HDLC_HEADER_RAW_SIZE);
  FATAL_SYSCALL_ON(frame->hdlc_header == NULL);

  // Form the HDLC header
  total_length = (frame->data_length != 0) ? (uint16_t)(frame->data_length + 2) : 0;

  frame_type = hdlc_get_frame_type(frame->control);

  if (frame_type == SLI_CPC_HDLC_FRAME_TYPE_INFORMATION) {
    hdlc_set_control_ack(&frame->control, frame->endpoint->ack);
  } else if (frame_type == SLI_CPC_HDLC_FRAME_TYPE_UNNUMBERED) {
    BUG_ON(frame->endpoint->id != SL_CPC_ENDPOINT_SYSTEM);
  }

  bool encrypt = should_encrypt_frame(frame);
  if (encrypt) {
    // if security subsystem is not ready yet and the frame must be encrypted
    // delay its transmission until ready
    if (!security_is_ready()) {
      WARN("Tried to encrypt an I-Frame on endpoint #%d but security is not ready. "
           "Moving packet to pending on security queue", frame->endpoint->id);
      sl_slist_push_back(&pending_on_security_ready_queue, &item->node);

      // Return true to keep processing other packets in the queue
      return true;
    }

    TRACE_CORE("Security: Encrypting frame on ep #%d", frame->endpoint->id);
  }

#if defined(ENABLE_ENCRYPTION)
  uint16_t security_buffer_size = 0;
  if (encrypt) {
    /* add up a few extra bytes to store security tag */
    security_buffer_size = (uint16_t)security_encrypt_get_extra_buffer_size();

    /* bug if the sum is going to overflow */
    BUG_ON(total_length > UINT16_MAX - security_buffer_size);
    total_length = (uint16_t)(total_length + security_buffer_size);
  }
#else
  BUG_ON(encrypt);
#endif

  /* create header after checking if the frame must be encrypted or not
   * as it has an impact on the total size of the payload, and the fcs */
  hdlc_create_header(frame->hdlc_header, frame->address, total_length, frame->control, true);

  uint16_t encrypted_data_length = frame->data_length;
  uint8_t *encrypted_payload = (uint8_t*)frame->data;

#if defined(ENABLE_ENCRYPTION)
  if (frame->endpoint && frame->re_transmit_count == 0u && encrypt) {
    frame->security_info = security_encrypt_prepare_next_frame(frame->endpoint);
  }

  if (encrypt) {
    uint8_t *security_offset;
    uint16_t fcs;
    sl_status_t encrypt_status;

    /*
     * encrypted_data_length is size of encrypted payload + size of security tag.
     * This operation should be safe to cast to uint16_t as it was already checked
     * earlier that the following sum doesn't overflow:
     *   total_length + security_buffer_size
     *
     * And total_length is frame->data_length + 2 bytes for the FCS.
     * So if the first operation doesn't overflow, this one won't as it's
     * two-byte shorter.
     */
    encrypted_data_length = (uint16_t)(frame->data_length + security_buffer_size);

    /* allocate buffer and make sure it succeeded */
    encrypted_payload = (uint8_t*)zalloc(encrypted_data_length);
    FATAL_ON(encrypted_payload == NULL);

    /*
     * compute offset at which security tag must be stored. It should be right
     * after the encrypted payload.
     */
    security_offset = &encrypted_payload[frame->data_length];

    /*
     * 'ack' in the control field of the header should be always set to 0
     * as it's not part of the authenticated data
     */
    uint8_t ack = hdlc_get_ack(hdlc_get_control(frame->hdlc_header));
    hdlc_set_control_ack(&((uint8_t*)frame->hdlc_header)[SLI_CPC_HDLC_CONTROL_POS], 0);

    encrypt_status = security_encrypt(frame->endpoint, frame->security_info,
                                      frame->hdlc_header, SLI_CPC_HDLC_HEADER_SIZE,
                                      frame->data, frame->data_length,
                                      encrypted_payload,
                                      security_offset, security_buffer_size);

    /*
     * restore 'ack' to its value
     */
    hdlc_set_control_ack(&((uint8_t*)frame->hdlc_header)[SLI_CPC_HDLC_CONTROL_POS], ack);

    if (encrypt_status != SL_STATUS_OK) {
      WARN("Encryption failed, leaving core_process_tx_queue");
      free(encrypted_payload);
      return false;
    }

    frame->security_session_last_packet = security_session_has_reset();
    security_session_reset_clear_flag();
    if (frame->security_session_last_packet) {
      security_session_last_packet_acked = false;
    }

    fcs = sli_cpc_get_crc_sw(encrypted_payload, (uint16_t)encrypted_data_length);
    frame->fcs[0] = (uint8_t)fcs;
    frame->fcs[1] = (uint8_t)(fcs >> 8);
  }
#else
  BUG_ON(encrypt);
#endif

  /* Construct and send the frame to the driver */
  {
    // total_length takes into account FCS and security tag
    size_t frame_length = SLI_CPC_HDLC_HEADER_RAW_SIZE + total_length;

    frame_t* frame_buffer = (frame_t*) zalloc(frame_length);
    FATAL_ON(frame_buffer == NULL);

    /* copy the header */
    memcpy(frame_buffer->header, frame->hdlc_header, SLI_CPC_HDLC_HEADER_RAW_SIZE);

    if (encrypted_data_length > 0) {
      /* copy the payload */
      memcpy(frame_buffer->payload, encrypted_payload, encrypted_data_length);

      memcpy(&frame_buffer->payload[encrypted_data_length], frame->fcs, sizeof(frame->fcs));
    }

    sl_slist_push_back(&pending_on_tx_complete, &item->node);
    core_push_frame_to_driver(frame_buffer, frame_length);

    if (frame->data != encrypted_payload) {
      /* in case a buffer was allocated for allocation, free it */
      free((void*)encrypted_payload);
    }

    free(frame_buffer);
  }

  TRACE_ENDPOINT_FRAME_TRANSMIT_SUBMITTED(frame->endpoint);

  return true;
}

/***************************************************************************//**
 * Callback for re-transmit frame
 ******************************************************************************/
static void re_transmit_timeout(sl_cpc_endpoint_t* endpoint)
{
  sl_cpc_transmit_queue_item_t *item;
  sl_cpc_buffer_handle_t *handle;
  sl_slist_node_t *node;

  node = endpoint->re_transmit_queue;
  BUG_ON(node == NULL);

  item = SL_SLIST_ENTRY(node, sl_cpc_transmit_queue_item_t, node);
  handle = item->handle;

  if (handle->re_transmit_count >= SLI_CPC_RE_TRANSMIT) {
    WARN("Retransmit limit reached on endpoint #%d", endpoint->id);
    core_set_endpoint_in_error(endpoint->id, SL_CPC_STATE_ERROR_DESTINATION_UNREACHABLE);
  } else {
    endpoint->re_transmit_timeout_ms *= 2; // RTO(new) = RTO(before retransmission) *2 )
                                           // this is explained in Karn’s Algorithm
    if (endpoint->re_transmit_timeout_ms > SL_CPC_MAX_RE_TRANSMIT_TIMEOUT_MS) {
      endpoint->re_transmit_timeout_ms = SL_CPC_MAX_RE_TRANSMIT_TIMEOUT_MS;
    }

    TRACE_CORE("New RTO calculated on ep %d, after re_transmit timeout: %ldms", endpoint->id, endpoint->re_transmit_timeout_ms);

    re_transmit_frame(endpoint);
  }
}

/***************************************************************************//**
 * Return true if the frame should be encrypted
 ******************************************************************************/
bool should_encrypt_frame(sl_cpc_buffer_handle_t *frame)
{
#if !defined(ENABLE_ENCRYPTION)
  (void)frame;

  return false;
#else
  uint8_t frame_control = frame->control;
  uint8_t frame_type = hdlc_get_frame_type(frame_control);
  uint16_t data_length = frame->data_length;
  sl_cpc_security_state_t state = security_get_state();

  if (state == SECURITY_STATE_DISABLED) {
    return false;
  }

  if (frame_type != SLI_CPC_HDLC_FRAME_TYPE_INFORMATION) {
    return false;
  }

  // If it's an I-Frame, the endpoint must be set
  BUG_ON(frame->endpoint == NULL);

  // If there is no payload, there is nothing to encrypt
  if (data_length == 0) {
    return false;
  }

  // Finally, rely on endpoint configuration
  return frame->endpoint->encrypted;
#endif
}

#if defined(ENABLE_ENCRYPTION)
static bool should_decrypt_frame(sl_cpc_endpoint_t *endpoint, uint16_t payload_len)
{
  /*
   * In normal mode of operation, security_state is set to INITIALIZED and
   * packets are decrypted below if they have a non-zero length. When the
   * security session is reset (for instance because the daemon sent a packet
   * that triggered an overflow), the secondary can still reply with encrypted
   * packets before it detects on its side that the security session should be
   * reset. So if packets are received while the state is RESETTING, we should
   * try to decrypt them.
   */
  sl_cpc_security_state_t security_state = security_get_state();

  if ((security_state != SECURITY_STATE_INITIALIZED
       && security_state != SECURITY_STATE_RESETTING)
      || security_state == SECURITY_STATE_DISABLED) {
    return false;
  }

  if (payload_len == 0) {
    return false;
  }

  if (!endpoint->encrypted) {
    return false;
  }

  if (security_state == SECURITY_STATE_RESETTING
      && security_session_last_packet_acked == true) {
    return false;
  } else {
    return true;
  }
}
#endif

static bool security_is_ready(void)
{
#if !defined(ENABLE_ENCRYPTION)
  return true;
#else
  sl_cpc_security_state_t security_state = security_get_state();

  return security_state == SECURITY_STATE_INITIALIZED
         || security_state == SECURITY_STATE_DISABLED;
#endif
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

#ifdef UNIT_TESTING
void core_reset_endpoint(uint8_t endpoint_number)
{
  sl_cpc_endpoint_t *ep;

  ep = &core_endpoints[endpoint_number];

  while (ep->state != SL_CPC_STATE_CLOSED) {
    sleep_ms(1);
  }

  // Cannot reset an open endpoint
  FATAL_ON(ep->state != SL_CPC_STATE_CLOSED);

  ep->id = endpoint_number;
  ep->seq = 0;
  ep->ack = 0;
  ep->frames_count_re_transmit_queue = 0;
  ep->current_tx_window_space = ep->configured_tx_window_size;
}

uint32_t core_endpoint_get_frame_counter(uint8_t endpoint_number, bool tx)
{
  sl_cpc_endpoint_t *ep = &core_endpoints[endpoint_number];

  if (tx) {
    return ep->frame_counter_tx;
  } else {
    return ep->frame_counter_rx;
  }
}

void core_endpoint_set_frame_counter(uint8_t endpoint_number, uint32_t new_value, bool tx)
{
  sl_cpc_endpoint_t *ep = &core_endpoints[endpoint_number];

  if (tx) {
    ep->frame_counter_tx = new_value;
  } else {
    ep->frame_counter_rx = new_value;
  }
}
#endif

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

static double diff_timespec_ms(const struct timespec *final, const struct timespec *initial)
{
  return (double)((final->tv_sec - initial->tv_sec) * 1000)
         + (double)(final->tv_nsec - initial->tv_nsec) / 1000000.0;
}

/***************************************************************************//**
 * Start the re-transmit timer for a given endpoint
 ******************************************************************************/
static void start_re_transmit_timer(sl_cpc_endpoint_t* endpoint, struct timespec offset)
{
  int ret;
  epoll_private_data_t* fd_timer_private_data;

  struct timespec current_timestamp;
  clock_gettime(CLOCK_MONOTONIC, &current_timestamp);

  long offset_in_ms;

  offset_in_ms = (long)diff_timespec_ms(&offset, &current_timestamp);

  fd_timer_private_data = endpoint->re_transmit_timer_private_data;

  if (offset_in_ms < 0) {
    offset_in_ms = 0;
  }

  if (endpoint->state != SL_CPC_STATE_OPEN) {
    return; // Don't start the timer if we're not open.
            // This can happen if a packet was still not sent to the bus
            // and an endpoint closed right after.
  }

  /* Make sure the timer file descriptor is open*/
  FATAL_ON(fd_timer_private_data == NULL);
  FATAL_ON(fd_timer_private_data->file_descriptor < 0);

  struct itimerspec timeout_time = { .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
                                     .it_value    = { .tv_sec = (signed)(((unsigned)offset_in_ms + endpoint->re_transmit_timeout_ms) / 1000),
                                                      .tv_nsec = (signed)((((unsigned)offset_in_ms + endpoint->re_transmit_timeout_ms) % 1000) * 1000000) } };

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
  TRACE_FRAME("Core : Pushed frame to driver : ", frame, frame_len);

  if (driver_sock_private_data.file_descriptor < 1) {
    TRACE_CORE("Core already closed the data socket");
    return;
  }

  ssize_t ret = send(driver_sock_private_data.file_descriptor, frame, frame_len, 0);

  /* Socket closed */
  if (ret < 0 && errno == ECONNRESET) {
    TRACE_CORE("Driver closed the data socket");
    epoll_unregister(&driver_sock_private_data);
    int ret_close = close(driver_sock_private_data.file_descriptor);
    FATAL_SYSCALL_ON(ret_close != 0);
    driver_sock_private_data.file_descriptor = -1;
    return;
  }

  FATAL_SYSCALL_ON(ret < 0);

  FATAL_ON((size_t) ret != frame_len);

  TRACE_CORE_TXD_TRANSMIT_COMPLETED();
}

/***************************************************************************//**
 * Fetches the next frame from the driver.
 *
 * The buffer for the retrieved frame is dynamically allocated inside this
 * function and passed to the caller. It is the caller's job to free the buffer
 * when done with it.
 *
 * Returns true is data is valid
 ******************************************************************************/
static bool core_pull_frame_from_driver(frame_t** frame_buf, size_t* frame_buf_len)
{
  size_t datagram_length;

  /* Poll the socket to get the next pending datagram size */
  {
    if (driver_sock_private_data.file_descriptor < 1) {
      TRACE_CORE("Core already closed the data socket");
      return false;
    }

    ssize_t retval = recv(driver_sock_private_data.file_descriptor, NULL, 0, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);

    /* Socket closed */
    if (retval == 0 || (retval < 0 && errno == ECONNRESET)) {
      TRACE_CORE("Driver closed the data socket");
      epoll_unregister(&driver_sock_private_data);
      int ret_close = close(driver_sock_private_data.file_descriptor);
      FATAL_SYSCALL_ON(ret_close != 0);
      driver_sock_private_data.file_descriptor = -1;
      return false;
    }

    FATAL_SYSCALL_ON(retval < 0);

    /* The socket had no data. This function is intended to be called
     * when we know the socket has data. */
    datagram_length = (size_t)retval;
    BUG_ON(datagram_length == 0);

    /* The length of the frame should be at minimum a header length */
    BUG_ON(datagram_length < sizeof(frame_t));
  }

  /* Allocate a buffer of the right size */
  {
    *frame_buf = (frame_t*) zalloc((size_t)datagram_length);
    FATAL_SYSCALL_ON(*frame_buf == NULL);
  }

  /* Fetch the datagram from the driver socket */
  {
    ssize_t ret = recv(driver_sock_private_data.file_descriptor, *frame_buf, (size_t)datagram_length, 0);

    FATAL_SYSCALL_ON(ret < 0);

    /* The next pending datagram size should be equal to what we just read */
    FATAL_ON((size_t)ret != (size_t)datagram_length);
  }

  *frame_buf_len = (size_t)datagram_length;
  return true;
}

/***************************************************************************//**
 * Sends a data payload to the server
 *
 * When a payload is processed by the core and ready to be sent to it's endpoint
 * socket, the core calls this function with the endpoint id. This function
 * allocated momentarily a buffer to store the payload and metainformation to
 * communicate with the server, sends this buffer and then frees it.
 ******************************************************************************/
static sl_status_t core_push_data_to_server(uint8_t ep_id, const void *data, size_t data_len)
{
  return server_push_data_to_endpoint(ep_id, data, data_len);
}
