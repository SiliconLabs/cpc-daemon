/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) - UART driver
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
#define _GNU_SOURCE

#include <pthread.h>

#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <signal.h>
#include <linux/serial.h>

#include "cpcd/board_controller.h"
#include "cpcd/config.h"
#include "cpcd/logging.h"
#include "cpcd/sleep.h"
#include "cpcd/utils.h"

#include "driver/driver_uart.h"
#include "server_core/core/hdlc.h"
#include "server_core/core/crc.h"
#include "driver/driver_kill.h"

#define UART_BUFFER_SIZE 4096 + SLI_CPC_HDLC_HEADER_RAW_SIZE
#define MAX_EPOLL_EVENTS 1

static int fd_uart;
static int fd_core;
static int fd_core_notify;
static int fd_stop_drv;
static unsigned int device_baudrate = 0;
static pthread_t rx_drv_thread;
static pthread_t tx_drv_thread;
static pthread_t cleanup_thread;

static void* receive_driver_thread_func(void* param);

static void* transmit_driver_thread_func(void* param);

static void driver_uart_process_uart(void);

static void driver_uart_process_core(void);

typedef struct notify_private_data{
  int timer_file_descriptor;
}notify_private_data_t;

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

static void* driver_uart_cleanup(void *param);

pthread_t driver_uart_init(int *fd_to_core, int *fd_notify_core, const char *device, unsigned int baudrate, bool hardflow)
{
  int fd_sockets[2];
  int fd_sockets_notify[2];
  ssize_t ret;

  fd_uart = driver_uart_open(device, baudrate, hardflow);

  /* Flush the uart IO fifo */
  tcflush(fd_uart, TCIOFLUSH);

  ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets);
  FATAL_SYSCALL_ON(ret < 0);

  fd_core  = fd_sockets[0];
  *fd_to_core = fd_sockets[1];

  ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets_notify);
  FATAL_SYSCALL_ON(ret < 0);

  fd_core_notify  = fd_sockets_notify[0];
  *fd_notify_core = fd_sockets_notify[1];

  /*
   * Create stop driver event, this file descriptor will be used by
   * receive and transmit thread to exit gracefully
   */
  fd_stop_drv = driver_kill_init();

  /* create transmitter driver thread */
  ret = pthread_create(&tx_drv_thread, NULL, transmit_driver_thread_func, NULL);
  FATAL_ON(ret != 0);

  /* create receiver driver thread */
  ret = pthread_create(&rx_drv_thread, NULL, receive_driver_thread_func, NULL);
  FATAL_ON(ret != 0);

  /* create cleanup thread */
  ret = pthread_create(&cleanup_thread, NULL, driver_uart_cleanup, NULL);
  FATAL_ON(ret != 0);

  ret = pthread_setname_np(tx_drv_thread, "tx_drv_thread");
  FATAL_ON(ret != 0);

  ret = pthread_setname_np(rx_drv_thread, "rx_drv_thread");
  FATAL_ON(ret != 0);

  TRACE_DRIVER("Opening uart file %s", device);

  TRACE_DRIVER("Init done");

  return cleanup_thread;
}

/***************************************************************************//**
 * @brief
 *   Probes the secondary to see if the bootloader is running
 *
 * The maneuver consists of sending a Carriage-Return character and waiting
 * too see if we receive the gecko bootloader prompt.
 *
 * @return
 *   true if the bootloader is running, false otherwise
 ******************************************************************************/
bool driver_uart_is_bootloader_running(const char *device, unsigned int baudrate, bool hardflow)
{
  bool bootloader_alive = true; // Return value
  // Start of bootloader prompt for compare purposes
  const char gecko_string[] = "\r\nGecko";
  // The full bootloader prompt is 71 characters long. Have an arbitrarily slightly longer receive buffer
  char prompt_buffer[128] = { 0 };

  fd_uart = driver_uart_open(device, baudrate, hardflow);
  tcflush(fd_uart, TCIOFLUSH);

  // Send the carriage-return
  {
    const uint8_t cr = '\r';

    ssize_t write_retval = write(fd_uart, &cr, sizeof(cr));
    FATAL_SYSCALL_ON(write_retval < 0);
  }

  // Wait a reasonable amount of time to receive the start of the prompt
  #define USEC_IN_SEC 1000000
  #define BITS_PER_UART_BYTE 10
  #define GECKO_STRING_USEC (useconds_t)((USEC_IN_SEC * sizeof(gecko_string) * BITS_PER_UART_BYTE) / baudrate)
  #define BOOTLOADER_SAFE_MARGIN_USEC (useconds_t) 200

  sleep_us(GECKO_STRING_USEC + BOOTLOADER_SAFE_MARGIN_USEC);

  // Check if we received data
  {
    int nread;

    ssize_t ret = ioctl(fd_uart, FIONREAD, &nread);
    FATAL_SYSCALL_ON(ret < 0);

    if (nread <= 0) {
      // If we received nothing, it is safe to assume the bootloader is NOT running, exit now
      bootloader_alive = false;
      goto ret;
    }
  }

  // Read the data into the temp buffer
  ssize_t read_retval = read(fd_uart, prompt_buffer, sizeof(prompt_buffer));
  FATAL_SYSCALL_ON(read_retval < 0);

  // Check if the received data contains the start of the prompt
  if (!strstr(prompt_buffer, gecko_string)) {
    // If we haven't received back the beginning of the bootloader prompt by now, it is safe
    // to assume the bootloader isn't running.
    bootloader_alive = false;
    goto ret;
  }

  // Wait for the end of the bootloader prompt "BL > "
  #define BOOTLOADER_PROMPT_LENGTH 71
  #define MSEC_IN_SEC 1000
  #define GECKO_STRING_MSEC ((USEC_IN_SEC * BOOTLOADER_PROMPT_LENGTH * BITS_PER_UART_BYTE) / baudrate)
  #define GECKO_STRING_SAFE_MARGIN_MSEC 2

  size_t i = (unsigned)read_retval;
  size_t time_elapsed_ms = 0;
  do {
    if (time_elapsed_ms == (GECKO_STRING_MSEC + GECKO_STRING_SAFE_MARGIN_MSEC)) {
      BUG("Received the beginning of the bootloader prompt but never received the end under 10ms");
    }

    sleep_us(1000);

    int nread;

    ssize_t ret = ioctl(fd_uart, FIONREAD, &nread);
    FATAL_SYSCALL_ON(ret < 0);

    if (nread > 0) {
      read_retval = read(fd_uart, &prompt_buffer[i], sizeof(prompt_buffer) - i);
      FATAL_ON(read_retval < 0);
    } else {
      read_retval = 0;
    }

    time_elapsed_ms++;
    i += (unsigned) read_retval;
  } while (!strstr(prompt_buffer, "BL > "));

  ret:
  close(fd_uart);
  return bootloader_alive;
}

void driver_uart_print_overruns(void)
{
  struct serial_icounter_struct counters;
  int retval = ioctl(fd_uart, TIOCGICOUNT, &counters);
  FATAL_SYSCALL_ON(retval < 0);
  TRACE_DRIVER("Overruns %d,%d", counters.overrun, counters.buf_overrun);
}

static void* driver_uart_cleanup(void *param)
{
  (void) param;

  // wait for threads to exit
  pthread_join(tx_drv_thread, NULL);
  pthread_join(rx_drv_thread, NULL);

  TRACE_DRIVER("Uart driver threads cancelled");

  close(fd_uart);
  close(fd_core);
  close(fd_core_notify);
  close(fd_stop_drv);

  pthread_exit(NULL);
  return NULL;
}

static void* receive_driver_thread_func(void* param)
{
  struct epoll_event events[2] = {};
  bool exit_thread = false;
  int fd_epoll;
  int ret;

  (void) param;

  TRACE_DRIVER("Receiver thread start");

  /* Create the epoll set */
  fd_epoll = epoll_create1(EPOLL_CLOEXEC);
  FATAL_SYSCALL_ON(fd_epoll < 0);

  /* Setup poll event for reading uart device */
  events[0].events = EPOLLIN;
  events[0].data.fd = fd_uart;
  ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_uart, &events[0]);
  FATAL_SYSCALL_ON(ret < 0);

  /* Setup poll event for stop event */
  events[1].events = EPOLLIN;
  events[1].data.fd = fd_stop_drv;
  ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_stop_drv, &events[1]);
  FATAL_SYSCALL_ON(ret < 0);

  while (!exit_thread) {
    int event_count;

    /* Wait for action */
    {
      do {
        event_count = epoll_wait(fd_epoll, events, 2, -1);
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
        int current_event_fd = events[event_i].data.fd;

        if (current_event_fd == fd_uart) {
          driver_uart_process_uart();
        } else if (current_event_fd == fd_stop_drv) {
          exit_thread = true;
        }
      }
    }
  }

  close(fd_epoll);

  return 0;
}

static void* transmit_driver_thread_func(void* param)
{
  struct epoll_event events[2] = {};
  bool exit_thread = false;
  int fd_epoll;
  int ret;

  (void) param;

  TRACE_DRIVER("Transmitter thread start");

  /* Create the epoll set */
  fd_epoll = epoll_create1(EPOLL_CLOEXEC);
  FATAL_SYSCALL_ON(fd_epoll < 0);

  /* Setup poll event for reading core socket */
  events[0].events = EPOLLIN;
  events[0].data.fd = fd_core;
  ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_core, &events[0]);
  FATAL_SYSCALL_ON(ret < 0);

  /* Setup poll event for stop event */
  events[1].events = EPOLLIN;
  events[1].data.fd = fd_stop_drv;
  ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_stop_drv, &events[1]);
  FATAL_SYSCALL_ON(ret < 0);

  while (!exit_thread) {
    int event_count;

    /* Wait for action */
    {
      do {
        event_count = epoll_wait(fd_epoll, events, 2, -1);
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
        int current_event_fd = events[event_i].data.fd;

        if (current_event_fd == fd_core) {
          driver_uart_process_core();
        } else if (current_event_fd == fd_stop_drv) {
          exit_thread = true;
        }
      }
    }
  }

  close(fd_epoll);

  return 0;
}

int driver_uart_open(const char *device, unsigned int baudrate, bool hardflow)
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
  int sym_baudrate = -1;
  int fd;

  fd = open(device, O_RDWR | O_CLOEXEC);
  FATAL_SYSCALL_ON(fd < 0);

  FATAL_SYSCALL_ON(tcgetattr(fd, &tty) < 0);

  size_t i;
  for (i = 0; i < ARRAY_SIZE(conversion); i++) {
    if (conversion[i].val == baudrate) {
      sym_baudrate = conversion[i].symbolic;
    }
  }

  if (sym_baudrate < 0) {
    FATAL("invalid baudrate: %d", baudrate);
  }

  cfsetispeed(&tty, (speed_t)sym_baudrate);
  cfsetospeed(&tty, (speed_t)sym_baudrate);
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
    sleep_ms(10);

    tcflush(fd, TCIOFLUSH);
  }

  if (config.board_controller_ip_addr) {
    unsigned int bc_baudrate;
    bool bc_flowcontrol;

    TRACE_DRIVER("Fetching Board Controller (%s) configuration...", config.board_controller_ip_addr);
    board_controller_get_config_vcom(config.board_controller_ip_addr, &bc_baudrate, &bc_flowcontrol);

    // Allow a baudrate error (determined on the board controller firmware to be 2% of the configured baudrate)
    unsigned int baudrate_error = (unsigned int)(config.uart_baudrate * 0.02);
    if (((unsigned int)(abs((int)bc_baudrate - (int)config.uart_baudrate)) > baudrate_error) || bc_flowcontrol != config.uart_hardflow) {
      FATAL("FAILURE : Host (Baudrate: %d, Flow control: %s), Board Controller (Baudrate: %d, Flow control: %s)", config.uart_baudrate, config.uart_hardflow == 1 ? "True" : "False", bc_baudrate, bc_flowcontrol  == 1 ? "True" : "False");
    } else {
      TRACE_DRIVER("SUCCESS : Host (Baudrate: %d, Flow control: %s), Board Controller (Baudrate: %d, Flow control: %s)", config.uart_baudrate, config.uart_hardflow == 1 ? "True" : "False", bc_baudrate, bc_flowcontrol  == 1 ? "True" : "False");
    }
  }

  device_baudrate = baudrate;

  return fd;
}

void driver_uart_assert_rts(bool assert)
{
  int ret;
  int flag = TIOCM_RTS;

  FATAL_ON(fd_uart < 0);

  if (assert) {
    ret = ioctl(fd_uart, TIOCMBIS, &flag);
  } else {
    ret = ioctl(fd_uart, TIOCMBIC, &flag);
  }

  FATAL_SYSCALL_ON(ret < 0);
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

static long driver_get_time_to_drain_ns(uint32_t bytes_left)
{
  BUG_ON(device_baudrate == 0);
  uint64_t nanoseconds;
  uint64_t bytes_per_sec = device_baudrate / 8;

  nanoseconds = bytes_left * (uint64_t)1000000000 / bytes_per_sec;

  return (long)(nanoseconds);
}

static void driver_uart_process_core(void)
{
  int ret;
  int length;
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

  ret = ioctl(fd_uart, TIOCOUTQ, &length);
  TRACE_DRIVER("%d bytes left in the UART char driver", length);
  FATAL_SYSCALL_ON(ret < 0);

  struct timespec tx_complete_timestamp;
  clock_gettime(CLOCK_MONOTONIC, &tx_complete_timestamp);

  if (tx_complete_timestamp.tv_nsec + driver_get_time_to_drain_ns((uint32_t)length) > 1000000000) {
    tx_complete_timestamp.tv_sec += (tx_complete_timestamp.tv_nsec + driver_get_time_to_drain_ns((uint32_t)length)) / 1000000000;
  }
  tx_complete_timestamp.tv_nsec += driver_get_time_to_drain_ns((uint32_t)length);
  tx_complete_timestamp.tv_nsec %= 1000000000;

  /* Push write notification to core */
  ssize_t write_retval = write(fd_core_notify, &tx_complete_timestamp, sizeof(tx_complete_timestamp));
  FATAL_SYSCALL_ON(write_retval != sizeof(tx_complete_timestamp));
}
