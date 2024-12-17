/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - CPC SDIO driver
 *******************************************************************************
 * # License
 * <b>Copyright 2024 Silicon Laboratories Inc. www.silabs.com</b>
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
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "cpcd/logging.h"
#include "cpcd/sleep.h"

#include "driver/driver_kill.h"
#include "driver/driver_sdio.h"

#include "driver/netlink/nl_sdio_interface.h"
#include "driver/netlink/nl_socket.h"

#include "server_core/core/crc.h"
#include "server_core/core/hdlc.h"

#define IRQ_LINE_TIMEOUT  10
#define MAX_EPOLL_EVENTS 5
#define SDIO_BUFFER_SIZE 4096
#define NETLINK_HEADER_SIZE 24

static int fd_core;
static int fd_core_notify;
static int fd_epoll;
static int fd_event_kill;
static pthread_t drv_thread;
static bool drv_thread_started = false;

typedef void (*driver_epoll_callback_t)(void);

static int validate_header(const uint8_t *header);
static uint16_t get_data_size(const uint8_t *header);

static void* driver_thread_func(void* param);
static void driver_sdio_process_core(void);
static ssize_t write_to_core(const uint8_t *rx_buffer, size_t write_size);

void driver_sdio_init(int *fd_to_core, int *fd_notify_core);

void driver_sdio_kill(void)
{
  // signal threads to exit
  ssize_t ret;
  const uint64_t event_value = 1; // Doesn't matter what it is
  if (drv_thread_started) {
    // signal and wait for thread to exit
    ret = write(fd_event_kill, &event_value, sizeof(event_value));
    FATAL_SYSCALL_ON(ret != sizeof(event_value));
    pthread_join(drv_thread, NULL);
  }
}

static ssize_t write_to_core(const uint8_t *rx_buffer, size_t write_size)
{
  return write(fd_core, rx_buffer, write_size);
}

static void driver_sdio_cleanup(void)
{
  int sts_ioctl;
  int sts_sd;
  const sli_linux_driver_cb_t *driver_cbPtr = &sli_linux_driver_app_cb;

  close(fd_core);
  close(fd_core_notify);
  close(fd_epoll);
  sts_ioctl = close(driver_cbPtr->ioctl_sd);
  sts_sd = close(driver_cbPtr->nl_sd);

  TRACE_DRIVER("SDIO driver thread cancelled");
  TRACE_DRIVER("EXT_HOST : SDIO Cleanup : Close socket status :IOCTL: %d, NLK = %d", sts_ioctl, sts_sd);

  drv_thread_started = false;
  pthread_exit(NULL);
}

void driver_sdio_init(int *fd_to_core,
                      int *fd_notify_core)
{
  int fd_sockets[2];
  int fd_sockets_notify[2];
  ssize_t ret;
  int status;

  ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets);
  FATAL_SYSCALL_ON(ret < 0);

  fd_core  = fd_sockets[0];
  *fd_to_core = fd_sockets[1];

  ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets_notify);
  FATAL_SYSCALL_ON(ret < 0);

  fd_core_notify  = fd_sockets_notify[0];
  *fd_notify_core = fd_sockets_notify[1];

  status = sl_nl_sdio_init();
  FATAL_ON(status != 0);

  // Setup epoll
  struct epoll_event event = { 0 };

  // Create the epoll set
  fd_epoll = epoll_create1(EPOLL_CLOEXEC);
  FATAL_SYSCALL_ON(fd_epoll < 0);

  // Setup the socket to the core
  event.events = EPOLLIN; // Level-triggered read() availability
  event.data.ptr = &driver_sdio_process_core;
  ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_core, &event);
  FATAL_SYSCALL_ON(ret < 0);

  // Setup the kill file descriptor
  fd_event_kill = eventfd(0, EFD_CLOEXEC);
  FATAL_SYSCALL_ON(fd_event_kill == -1);
  driver_kill_init(driver_sdio_kill);

  event.events = EPOLLIN; // Level-triggered read() availability
  event.data.ptr = &driver_sdio_cleanup;
  ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_event_kill, &event);
  FATAL_SYSCALL_ON(ret < 0);

  // create driver thread
  ret = pthread_create(&drv_thread, NULL, driver_thread_func, NULL);
  FATAL_ON(ret != 0);

  drv_thread_started = true;

  ret = pthread_setname_np(drv_thread, "drv_thread");
  FATAL_ON(ret != 0);

  ret = nl_sdio_interface_register_irq();
  FATAL_ON(ret < 0);

  TRACE_DRIVER("Init done");
}

static void* driver_thread_func(void* param)
{
  (void) param;
  struct epoll_event events[MAX_EPOLL_EVENTS] = {};
  int event_count;

  TRACE_DRIVER("Thread start");

  while (1) {
    // Wait for action
    do {
      event_count = epoll_wait(fd_epoll, events, MAX_EPOLL_EVENTS, -1);
      if (event_count == -1 && errno == EINTR) {
        continue;
      }
      FATAL_SYSCALL_ON(event_count == -1);
      break;
    } while (1);

    // Timeouts should not occur
    FATAL_ON(event_count == 0);

    TRACE_DRIVER("Received Event");

    // Process each ready file descriptor
    for (int event_i = 0; event_i != event_count; event_i++) {
      driver_epoll_callback_t callback = (driver_epoll_callback_t) events[event_i].data.ptr;
      callback();
    }
  }

  return NULL;
}

void * RecvThreadBody(void * arg)
{
  (void) arg;
  ssize_t rsp_len;
  int ret;
  size_t payload_size;
  size_t write_size;
  uint8_t rx_buffer[SDIO_BUFFER_SIZE];
  uint8_t rx_buffer_valid[SDIO_BUFFER_SIZE];
  ssize_t write_retval;

  while (1) {
    rsp_len = recv(sli_linux_driver_app_cb.nl_sd, rx_buffer, (SLI_NL_APP_MAX_PAYLOAD_SIZE - NETLINK_HEADER_SIZE), 0);

    if (rsp_len < 0) {
      TRACE_DRIVER(" RecvThreadBody ERROR NUMBER = %d", errno);
      if (errno == ENOBUFS || errno == ESPIPE) {
        // Handling for No buffer space available Error
        continue;
      }
      return NULL;
    }

    mempcpy(&rx_buffer_valid[0], &rx_buffer[NETLINK_HEADER_SIZE], (size_t)(rsp_len - NETLINK_HEADER_SIZE));
    ret = validate_header(rx_buffer_valid);
    FATAL_ON(ret != 0);

    payload_size = (size_t)get_data_size(rx_buffer_valid);
    if (payload_size > 0) {
      write_size = payload_size + SLI_CPC_HDLC_HEADER_RAW_SIZE;
    } else if (payload_size == 0) {
      write_size = SLI_CPC_HDLC_HEADER_RAW_SIZE;
    }

    write_retval = write_to_core(rx_buffer_valid, write_size);
    FATAL_SYSCALL_ON(write_retval < 0);

    TRACE_FRAME("Driver :RX  flushed frame to core : ", rx_buffer_valid, (size_t)write_retval);
  }
}

static int validate_header(const uint8_t *header)
{
  uint16_t hcs;
  if (header[SLI_CPC_HDLC_FLAG_POS] == SLI_CPC_HDLC_FLAG_VAL) {
    hcs = sli_cpc_get_crc_sw(header, SLI_CPC_HDLC_HEADER_SIZE);
    if (hcs == hdlc_get_hcs(header)) {
      return 0;
    } else {
      TRACE_DRIVER_INVALID_HEADER_CHECKSUM();
      return -1;
    }
  } else {
    TRACE_DRIVER("Invalid header");
    return -1;
  }
}

static uint16_t get_data_size(const uint8_t *header)
{
  return hdlc_get_length(header);
}

static void driver_sdio_process_core(void)
{
  uint8_t buffer[SDIO_BUFFER_SIZE];
  size_t read_retval;
  ssize_t ret;

  read_retval = (size_t)read(fd_core, buffer, sizeof(buffer));
  FATAL_ON(read_retval > UINT16_MAX);

  ret = sli_execute_cmd(&buffer[0], &buffer[SLI_CPC_HDLC_HEADER_RAW_SIZE], sizeof(buffer));
  FATAL_ON(ret < 0);

  // Wait for the sdio driver in the kernel to receive and process the SDIO command
  sleep_us(1000);

  struct timespec tx_complete_timestamp;
  clock_gettime(CLOCK_MONOTONIC, &tx_complete_timestamp);

  // Push write notification to core
  ssize_t write_retval = write(fd_core_notify, &tx_complete_timestamp, sizeof(tx_complete_timestamp));
  FATAL_SYSCALL_ON(write_retval != sizeof(tx_complete_timestamp));
}
