/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) - UART driver
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
#define _GNU_SOURCE
#include <pthread.h>

#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <linux/serial.h>

#include "misc/logging.h"
#include "misc/utils.h"
#include "driver/driver_uart.h"
#include "server_core/core/hdlc.h"
#include "server_core/core/crc.h"
#include "driver/driver_kill.h"

#define UART_BUFFER_SIZE 4096 + SLI_CPC_HDLC_HEADER_RAW_SIZE
#define MAX_EPOLL_EVENTS 5

static int fd_uart;
static int fd_core;
static int fd_epoll;
static pthread_t rx_drv_thread;
static pthread_t tx_drv_thread;
static pthread_t cleanup_thread;
static unsigned int uart_bitrate;

typedef void (*driver_epoll_callback_t)(void);

static void* cleanup_thread_func(void* param);

static void* receive_driver_thread_func(void* param);

static void* transmit_driver_thread_func(void* param);

static void driver_uart_process_uart(void);

static void driver_uart_process_core(void);

/*
 * @return The number of bytes appended to the buffer
 */
static size_t read_and_append_uart_received_data(uint8_t *buffer, size_t buffer_head, size_t buffer_size);

/*
 * Call this function in loop over the buffer to delimit and push the frames to the core
 *
 * @return Whether or not this call has delimited a pushed a frame, in other words,
 *         shall this function be called again in a loop
 */
static bool delimit_and_push_frames_to_core(uint8_t *buffer, size_t *buffer_head);

/*
 * Insures the start of the buffer is aligned with the start of a valid checksum
 * and re-synch in case the buffer starts with garbage.
 */
static bool header_re_synch(uint8_t *buffer, size_t *buffer_head);

static void driver_uart_cleanup(void);

pthread_t driver_uart_init(int *fd_to_core, const char *device, unsigned int bitrate, bool hardflow)
{
  int fd_sockets[2];
  pthread_attr_t detach_attr;
  ssize_t ret;

  fd_uart = driver_uart_open(device, bitrate, hardflow);
  uart_bitrate = bitrate;

  /* Flush the uart IO fifo */

  tcflush(fd_uart, TCIOFLUSH);

  ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, fd_sockets);
  FATAL_SYSCALL_ON(ret < 0);

  fd_core  = fd_sockets[0];

  *fd_to_core = fd_sockets[1];

  /* Setup epoll */
  {
    struct epoll_event event = {};

    /* Create the epoll set */
    {
      fd_epoll = epoll_create1(EPOLL_CLOEXEC);
      FATAL_SYSCALL_ON(fd_epoll < 0);
    }

    /* Setup the kill file descriptor */
    {
      int eventfd_kill = driver_kill_init();

      event.events = EPOLLIN; /* Level-triggered read() availability */
      event.data.ptr = driver_uart_cleanup;

      ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, eventfd_kill, &event);
      FATAL_SYSCALL_ON(ret < 0);
    }
  }

  /* Init detach attribute */
  ret = pthread_attr_init(&detach_attr);
  FATAL_ON(ret != 0);

  /* Set detach attribute */
  ret = pthread_attr_setdetachstate(&detach_attr, PTHREAD_CREATE_DETACHED);
  FATAL_ON(ret != 0);

  /* create cleanup thread */
  ret = pthread_create(&cleanup_thread, NULL, cleanup_thread_func, NULL);
  FATAL_ON(ret != 0);

  /* create transmitter driver thread */
  ret = pthread_create(&tx_drv_thread, &detach_attr, transmit_driver_thread_func, NULL);
  FATAL_ON(ret != 0);

  /* create receiver driver thread */
  ret = pthread_create(&rx_drv_thread, &detach_attr, receive_driver_thread_func, NULL);
  FATAL_ON(ret != 0);

  ret = pthread_setname_np(tx_drv_thread, "tx_drv_thread");
  FATAL_ON(ret != 0);

  ret = pthread_setname_np(rx_drv_thread, "rx_drv_thread");
  FATAL_ON(ret != 0);

  TRACE_DRIVER("Opening uart file %s", device);

  TRACE_DRIVER("Init done");

  return cleanup_thread;
}

void driver_uart_print_overruns(void)
{
  struct serial_icounter_struct counters;
  int retval = ioctl(fd_uart, TIOCGICOUNT, &counters);
  FATAL_SYSCALL_ON(retval < 0);
  TRACE_DRIVER("Overruns %d,%d", counters.overrun, counters.buf_overrun);
}

static void driver_uart_cleanup(void)
{
  close(fd_uart);
  close(fd_core);
  close(fd_epoll);

  TRACE_DRIVER("Uart driver threads cancelled");

  (void)pthread_detach(tx_drv_thread);
  (void)pthread_detach(rx_drv_thread);
  pthread_exit(0);
}

static void* cleanup_thread_func(void* param)
{
  (void) param;
  struct epoll_event events[MAX_EPOLL_EVENTS] = {};

  TRACE_DRIVER("Cleanup thread start");

  while (1) {
    int event_count;

    /* Wait for action */
    {
      do {
        event_count = epoll_wait(fd_epoll, events, MAX_EPOLL_EVENTS, -1);
        if (event_count == -1 && errno == EINTR) {
          continue;
        }
        FATAL_SYSCALL_ON(event_count == -1);
        break;
      } while (1);

      /* Timeouts should not occur */
      FATAL_ON(event_count == 0);
    }

    /* Process each ready file descriptor */
    {
      size_t event_i;
      for (event_i = 0; event_i != (size_t)event_count; event_i++) {
        driver_epoll_callback_t callback = (driver_epoll_callback_t) events[event_i].data.ptr;
        callback();
      }
    }
  } //while(1)

  return 0;
}

static void* receive_driver_thread_func(void* param)
{
  (void) param;

  TRACE_DRIVER("Receiver thread start");

  while (1) {
    driver_uart_process_uart();
  } //while(1)

  return 0;
}

static void* transmit_driver_thread_func(void* param)
{
  (void) param;

  TRACE_DRIVER("Transmitter thread start");

  while (1) {
    driver_uart_process_core();
  } //while(1)

  return 0;
}

int driver_uart_open(const char *device, unsigned int bitrate, bool hardflow)
{
  static const struct {
    unsigned int val;
    int symbolic;
  } conversion[] = {
    { 9600, B9600 },
    { 19200, B19200 },
    { 38400, B38400 },
    { 57600, B57600 },
    { 115200, B115200 },
    { 230400, B230400 },
    { 460800, B460800 },
    { 921600, B921600 },
  };
  struct termios tty;
  int sym_bitrate = -1;
  int fd;

  fd = open(device, O_RDWR | O_CLOEXEC);
  FATAL_SYSCALL_ON(fd < 0);

  FATAL_SYSCALL_ON(tcgetattr(fd, &tty) < 0);

  size_t i;
  for (i = 0; i < ARRAY_SIZE(conversion); i++) {
    if (conversion[i].val == bitrate) {
      sym_bitrate = conversion[i].symbolic;
    }
  }

  if (sym_bitrate < 0) {
    FATAL("invalid bitrate: %d", bitrate);
  }

  cfsetispeed(&tty, (speed_t)sym_bitrate);
  cfsetospeed(&tty, (speed_t)sym_bitrate);
  cfmakeraw(&tty);
  /* Nonblocking read. */
  tty.c_cc[VTIME] = 0;
  tty.c_cc[VMIN] = 1;
  tty.c_iflag &= (unsigned) ~(IXON);
  tty.c_iflag &= (unsigned) ~(IXOFF);
  tty.c_iflag &= (unsigned) ~(IXANY);
  tty.c_cflag &= (unsigned) ~(HUPCL);
  tty.c_cflag |= CLOCAL;
  if (hardflow) {
    tty.c_cflag |= CRTSCTS;
  } else {
    tty.c_cflag &= ~CRTSCTS;
  }

  FATAL_SYSCALL_ON(tcsetattr(fd, TCSANOW, &tty) < 0);

  /* Flush the content of the UART in case there was stale data */
  {
    /* There was once a bug in the kernel requiring a delay before flushing the uart.
     * Keep it there for backward compatibility */
    usleep(10000);

    tcflush(fd, TCIOFLUSH);
  }

  return fd;
}

static void driver_uart_process_uart(void)
{
  static uint8_t buffer[UART_BUFFER_SIZE];
  static size_t buffer_head = 0;
  static enum {EXPECTING_HEADER, EXPECTING_PAYLOAD} state = EXPECTING_HEADER;

  /* Put the read data at the tip of the buffer head and increment it. */
  buffer_head += read_and_append_uart_received_data(buffer, buffer_head, sizeof(buffer));

  while (1) {
    switch (state) {
      case EXPECTING_HEADER:
        /* Synchronize the start of 'buffer' with the start of a valid header with valid checksum. */
        if (header_re_synch(buffer, &buffer_head)) {
          /* We are synchronized on a valid header, start delimiting the data that follows into a frame. */
          state = EXPECTING_PAYLOAD;
        } else {
          /* We went through all the data contained in 'buffer' and haven't synchronized on a header.
           * Go back to waiting for more data. */
          return;
        }
        break;

      case EXPECTING_PAYLOAD:
        if (delimit_and_push_frames_to_core(buffer, &buffer_head)) {
          /* A frame has been delimited and pushed to the core, go back to synchronizing on the next header */
          state = EXPECTING_HEADER;
        } else {
          /* Not yet enough data, go back to waiting. */
          return;
        }
        break;

      default:

        BUG("Illegal switch, Case : %d", state);
        break;
    }
  }
}

/* Append UART new data to the frame delimiter processing buffer */
static size_t read_and_append_uart_received_data(uint8_t *buffer, size_t buffer_head, size_t buffer_size)
{
  uint8_t temp_buffer[UART_BUFFER_SIZE];

  BUG_ON(buffer_head >= buffer_size);

  /* Make sure we don't read more data than the supplied buffer can handle */
  const size_t available_space = buffer_size - buffer_head - 1;

  /* Read the uart data into the temp buffer */
  ssize_t read_retval = read(fd_uart, temp_buffer, available_space);
  FATAL_ON(read_retval < 0);

  /* copy the data in the main buffer */
  memcpy(&buffer[buffer_head], temp_buffer, (size_t)read_retval);

  return (size_t)read_retval;
}

static bool validate_header(uint8_t *header_start)
{
  uint16_t hcs;

  if (header_start[SLI_CPC_HDLC_FLAG_POS] != SLI_CPC_HDLC_FLAG_VAL) {
    return false;
  }

  hcs = hdlc_get_hcs(header_start);

  if (!sli_cpc_validate_crc_sw(header_start, SLI_CPC_HDLC_HEADER_SIZE, hcs)) {
    TRACE_DRIVER_INVALID_HEADER_CHECKSUM();
    return false;
  }

  return true;
}

static bool header_re_synch(uint8_t *buffer, size_t *buffer_head)
{
  if (*buffer_head < SLI_CPC_HDLC_HEADER_RAW_SIZE) {
    /* There's not enough data for a header, nothing to re-synch */
    return false;
  }

  /* If we think of a header like a sliding window of width SLI_CPC_HDLC_HEADER_RAW_SIZE,
   * then we can slide it 'num_header_combination' times over the data. */
  const size_t num_header_combination = *buffer_head - SLI_CPC_HDLC_HEADER_RAW_SIZE + 1;

  TRACE_DRIVER("re-sync : Will test %i header combination", num_header_combination);

  size_t i;

  for (i = 0; i != num_header_combination; i++) {
    if (validate_header(&buffer[i])) {
      if (i == 0) {
        /* The start of the buffer is aligned with a good header, don't do anything */
        TRACE_DRIVER("re-sync : The start of the buffer is aligned with a good header");
      } else {
        /* We had 'i' number of bad bytes until we struck a good header, move back the data
         * to the beginning of the buffer */
        memmove(&buffer[0], &buffer[i], *buffer_head - i);

        /* We crushed 'i' bytes at the start of the buffer */
        *buffer_head -= i;
        TRACE_DRIVER("re-sync : had '%u' number of bad bytes until we struck a good header", i);
      }
      return true;
    } else {
      /* The header is not valid, continue until it is */
    }
  }

  /* If we land here, no header at all was found. Keep the last 'SLI_CPC_HDLC_HEADER_RAW_SIZE - 1' bytes and
   * bring them back at the start of the buffer so that the next appended byte could complete that potential header */
  {
    memmove(&buffer[0], &buffer[num_header_combination], SLI_CPC_HDLC_HEADER_RAW_SIZE - 1);

    *buffer_head = SLI_CPC_HDLC_HEADER_RAW_SIZE - 1;
  }

  return false;
}

/*
 * In this function, it is assumed that the start of the buffer 'buffer' is aligned with the
 * start of a header because each time this function delimits a frame, it moves back the
 * remaining data back to the start of the buffer. Except when things go wrong, the start
 * if the remaining data will be the start of a next header.
 */
static bool delimit_and_push_frames_to_core(uint8_t *buffer, size_t *buffer_head)
{
  uint16_t payload_len; /* The length of the payload, as retrieved from the header (including the checksum) */
  size_t frame_size; /* The whole size of the frame */

  /* if not enough bytes even for a header */
  if (*buffer_head < SLI_CPC_HDLC_HEADER_RAW_SIZE) {
    return false;
  }

  payload_len = hdlc_get_length(buffer);

  frame_size = payload_len + SLI_CPC_HDLC_HEADER_RAW_SIZE;

  /* Check if we have enough data for a full frame*/
  if (frame_size > *buffer_head) {
    return false;
  }

  /* Push to core */
  {
    TRACE_FRAME("Driver : Frame delimiter : push delimited frame to core : ", buffer, frame_size);

    ssize_t write_retval = write(fd_core, buffer, frame_size);
    FATAL_SYSCALL_ON(write_retval < 0);

    /* Error if write is not complete */
    FATAL_ON((size_t)write_retval != frame_size);
  }

  /* Move the remaining data back to the start of the buffer. */
  {
    const size_t remaining_bytes = *buffer_head - frame_size;

    memmove(buffer, &buffer[frame_size], remaining_bytes);

    /* Adjust the buffer_head now that we have modified the buffer's content */
    *buffer_head = remaining_bytes;
  }

  /* A complete frame has been delimited. A second round of parsing can be done. */
  return true;
}

static void driver_uart_process_core(void)
{
  uint8_t buffer[UART_BUFFER_SIZE];
  ssize_t read_retval;

  {
    read_retval = read(fd_core, buffer, sizeof(buffer));

    FATAL_SYSCALL_ON(read_retval < 0);
  }

  {
    ssize_t write_retval = write(fd_uart, buffer, (size_t)read_retval);

    FATAL_SYSCALL_ON(write_retval < 0);

    /* Error if write is not complete */
    FATAL_ON((size_t)write_retval != (size_t)read_retval);
  }

  TRACE_FRAME("Driver : flushed frame to uart : ", buffer, (size_t)read_retval);
}
