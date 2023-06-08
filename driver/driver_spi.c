/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - CPC SPI driver
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
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>
#include <signal.h>
#include <string.h>

#include "cpcd/logging.h"
#include "cpcd/sleep.h"
#include "cpcd/config.h"
#include "cpcd/server_core.h"

#include "server_core/core/crc.h"
#include "server_core/core/hdlc.h"
#include "driver/driver_spi.h"
#include "driver/driver_kill.h"

// This value is a reasonable worst case estimate of the interrupt latency when RAIL is used for the radio
#define MAXIMUM_REASONABLE_INTERRUPT_LATENCY_US 500

static int fd_core;
static int fd_core_notify;
static int fd_epoll;
static pthread_t drv_thread;
static int spi_dev_descriptor;
static gpio_t irq_gpio;
static bool secondary_started = false;

typedef void (*driver_epoll_callback_t)(void);

static bool validate_header(uint8_t *header);
static int get_data_size(uint8_t *header);

static void driver_spi_event_core(void);
static void driver_spi_event_irq(void);
static void driver_spi_transaction(bool);
static void* driver_thread_func(void* param);

static void driver_spi_cleanup(void)
{
  close(spi_dev_descriptor);
  close(fd_core);
  close(fd_core_notify);
  close(fd_epoll);

  gpio_deinit(&irq_gpio);

  TRACE_DRIVER("SPI driver thread cancelled");

  pthread_exit(NULL);
}

pthread_t driver_spi_init(int *fd_to_core,
                          int *fd_notify_core,
                          const char *device,
                          unsigned int speed,
                          const char *irq_gpio_chip,
                          unsigned int irq_gpio_pin)
{
  int fd_sockets[2];
  int fd_sockets_notify[2];
  ssize_t ret;

  {
    spi_dev_descriptor = open(device, O_RDWR | O_CLOEXEC);
    FATAL_SYSCALL_ON(spi_dev_descriptor < 0);

    const unsigned int mode = SPI_MODE_0;
    ret = ioctl(spi_dev_descriptor, SPI_IOC_WR_MODE, &mode);
    FATAL_SYSCALL_ON(ret < 0);

    const unsigned int bit_per_word = 8;
    ret = ioctl(spi_dev_descriptor, SPI_IOC_WR_BITS_PER_WORD, &bit_per_word);
    FATAL_SYSCALL_ON(ret < 0);

    ret = ioctl(spi_dev_descriptor, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
    FATAL_SYSCALL_ON(ret < 0);

    // Setup IRQ gpio
    FATAL_ON(gpio_init(&irq_gpio, irq_gpio_chip, irq_gpio_pin, IN, FALLING) < 0);
  }

  ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets);
  FATAL_SYSCALL_ON(ret < 0);

  fd_core  = fd_sockets[0];
  *fd_to_core = fd_sockets[1];

  ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets_notify);
  FATAL_SYSCALL_ON(ret < 0);

  fd_core_notify  = fd_sockets_notify[0];
  *fd_notify_core = fd_sockets_notify[1];

  // Setup epoll
  {
    struct epoll_event event = {};

    // Create the epoll set
    {
      fd_epoll = epoll_create1(EPOLL_CLOEXEC);
      FATAL_SYSCALL_ON(fd_epoll < 0);
    }

    // Setup the socket to the core
    {
      event.events = EPOLLIN; // Level-triggered read() availability
      event.data.ptr = driver_spi_event_core;
      ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_core, &event);
      FATAL_SYSCALL_ON(ret < 0);
    }

    // Setup the spi
    {
      event.events = GPIO_EPOLL_EVENT; // Level-triggered read() availability
      event.data.ptr = driver_spi_event_irq;
      ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, gpio_get_fd(&irq_gpio), &event);
      FATAL_SYSCALL_ON(ret < 0);
    }

    // Setup the kill file descriptor
    {
      int eventfd_kill = driver_kill_init();
      event.events = EPOLLIN; // Level-triggered read() availability
      event.data.ptr = driver_spi_cleanup;
      ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, eventfd_kill, &event);
      FATAL_SYSCALL_ON(ret < 0);
    }
  }

  // create driver thread
  ret = pthread_create(&drv_thread, NULL, driver_thread_func, NULL);
  FATAL_ON(ret != 0);

  ret = pthread_setname_np(drv_thread, "drv_thread");
  FATAL_ON(ret != 0);

  TRACE_DRIVER("Opening spi file %s", device);

  TRACE_DRIVER("Init done");

  return drv_thread;
}

static void* driver_thread_func(void* param)
{
  (void) param;
  struct epoll_event event;
  int event_count;

  TRACE_DRIVER("Thread start");

  while (1) {
    // Wait for action
    {
      do {
        // Important here that this value stays to 1. We absolutely want to ask the kernel 1 file descriptor at a time
        // if is has activity. Since we can, from the epoll event of the IRQ line, read from the core socket to be able to
        // send at the same time we receive, it is possible to render the core file descriptor non-active by pulling the only
        // frame it contains.
        const int MAX_EPOLL_EVENTS = 1;

        event_count = epoll_wait(fd_epoll,
                                 &event,
                                 MAX_EPOLL_EVENTS,
                                 -1);

        if (event_count == -1 && errno == EINTR) {
          continue;
        }
        FATAL_SYSCALL_ON(event_count == -1);
        break;
      } while (1);

      // Timeouts should not occur
      FATAL_ON(event_count == 0);
    }

    // Process the ready file descriptor
    driver_epoll_callback_t callback = (driver_epoll_callback_t) event.data.ptr;
    callback();
  } //while(1)

  gpio_deinit(&irq_gpio);

  return 0;
}

static bool validate_header(uint8_t *header)
{
  if (header[SLI_CPC_HDLC_FLAG_POS] == SLI_CPC_HDLC_FLAG_VAL) {
    return true;
  } else {
    return false;
  }
}

static int get_data_size(uint8_t *header)
{
  uint16_t hcs;

  if (validate_header(header)) {
    hcs = sli_cpc_get_crc_sw(header, SLI_CPC_HDLC_HEADER_SIZE);

    if (hcs == hdlc_get_hcs(header)) {
      return (int)hdlc_get_length(header);
    } else {
      TRACE_DRIVER_INVALID_HEADER_CHECKSUM();
      return -1;
    }
  } else {
    return -1;
  }
}

static void driver_spi_event_core(void)
{
  driver_spi_transaction(false);
}

static void driver_spi_event_irq(void)
{
  driver_spi_transaction(true);
}

static long t2_minus_t1_us(struct timespec *t2, struct timespec *t1)
{
  long time_diff_sec = t2->tv_sec - t1->tv_sec;    // calculate time difference in seconds
  long time_diff_nsec = t2->tv_nsec - t1->tv_nsec; // calculate time difference in nanoseconds

  if (time_diff_nsec < 0) {
    --time_diff_sec;
    time_diff_nsec += 1000000000L;
  }

  long time_diff_microsec = time_diff_sec * 1000000 + time_diff_nsec / 1000; // convert to microseconds

  return time_diff_microsec;
}

/*
 * @return : true when the secondary asserted IRQ in time
 *           false when the secondary timed out to assert IRQ
 */
static bool wait_for_irq_assert_or_timeout(void)
{
  //TODO CPC-649 Rewrite this method

  // In 99.99% of the cases, the secondary executed its header interrupt and lowered IRQ before
  // the host even returns from the SPI ioctl transfer call. Try executing the minimal amount of logic
  // path first
  if (gpio_read(&irq_gpio) == 0u) {
    return true;
  }

  // The IRQ line is still high. It is known that the header interrupt is short, so if IRQ is still high
  // it means there likely was interrupt latency. In that case, its reasonable to busy loop against IRQ==0 because
  // IRQ should fall soon. The worst case interrupt latency we can reasonably expect from a secondary running a radio
  // is MAXIMUM_REASONABLE_INTERRUPT_LATENCY_US

  // Start by getting the current time
  struct timespec start_time;
  clock_gettime(CLOCK_MONOTONIC, &start_time);

  // Busy loop until IRQ==0 or timeout
  while (gpio_read(&irq_gpio) != 0u) {
    struct timespec now_time;
    clock_gettime(CLOCK_MONOTONIC, &now_time);

    // Timeout on 10 * MAXIMUM_REASONABLE_INTERRUPT_LATENCY_US
    if (t2_minus_t1_us(&now_time, &start_time) > (10 * MAXIMUM_REASONABLE_INTERRUPT_LATENCY_US)) {
      return false;
    }
  }

  return true;
}

static bool null_header(uint8_t* header)
{
  const uint8_t zeros[7] = { 0, 0, 0, 0, 0, 0, 0 };
  const uint8_t ones[7]  = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

  if (memcmp(header, zeros, sizeof(zeros)) == 0 || memcmp(header, ones, sizeof(ones)) == 0 ) {
    return true;
  }

  return false;
}

static void driver_spi_transaction(bool clear_irq)
{
  struct spi_ioc_transfer local_spi_transfer;
  size_t  tx_length = 0;
  uint8_t tx_buffer[SPI_BUFFER_SIZE] = { 0 }; // Holds the possible TX frame we could send to the secondary.
  size_t  rx_length = 0;
  uint8_t rx_buffer[SPI_BUFFER_SIZE]; // Holds the RX frame we read from the secondary
  size_t  payload_length = 0;
  bool    want_to_receive = false;
  bool    want_to_transmit = false;
  bool    rx_header_checksum_error = false;

  memset(&local_spi_transfer, 0x00, sizeof(local_spi_transfer));

  local_spi_transfer.speed_hz = server_core_max_bitrate_received() ? config.spi_bitrate : SPI_INITIAL_BITRATE;

  TRACE_DRIVER("Init of a transaction");

  if (clear_irq) {
    gpio_clear_irq(&irq_gpio);
  }

  // Check if the secondary is signaling it wants to send a frame.
  {
    int ret = gpio_read(&irq_gpio);
    FATAL_SYSCALL_ON(ret < 0);

    if (ret == 0) {
      want_to_receive = true;

      TRACE_DRIVER("secondary wants to send us something.");
    }
  }

  // Check if the host have something to send
  {
    ssize_t ret = recv(fd_core, NULL, 0, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
    FATAL_SYSCALL_ON(ret < 0 && (errno != EAGAIN && errno != EWOULDBLOCK));

    if (ret < 0 ) {
      tx_length = 0;
    } else {
      tx_length = (size_t) ret;
    }

    // Pull the frame if there is one
    if (tx_length > 0) {
      // Paranoia
      BUG_ON(tx_length < SLI_CPC_HDLC_HEADER_RAW_SIZE);

      want_to_transmit = true;

      // Get the effective payload length
      tx_length -= SLI_CPC_HDLC_HEADER_RAW_SIZE;

      TRACE_DRIVER("primary wants to send something");
    }
  }

  if (want_to_receive  == false && want_to_transmit == false) {
    // Flush previous latched IRQ falling edge event
    return;
  }

  // Pull transmit it from the core data socket.
  if (want_to_transmit) {
    ssize_t read_retval = read(fd_core, tx_buffer, sizeof(tx_buffer));
    FATAL_SYSCALL_ON(read_retval < 0);
    BUG_ON((size_t) read_retval != (tx_length + SLI_CPC_HDLC_HEADER_RAW_SIZE));
  }

  // Clock the header
  {
    if (want_to_transmit) {
      local_spi_transfer.tx_buf = (unsigned long) tx_buffer;
    } else {
      local_spi_transfer.tx_buf = (unsigned long) NULL; // Send 0s in case we just to a read
    }

    local_spi_transfer.rx_buf = (unsigned long) rx_buffer;

    local_spi_transfer.len = SLI_CPC_HDLC_HEADER_RAW_SIZE;

    int ret = ioctl(spi_dev_descriptor, SPI_IOC_MESSAGE(1), &local_spi_transfer);
    FATAL_ON(ret != (int)local_spi_transfer.len);

    TRACE_FRAME("Clocked in this header : ", rx_buffer, SLI_CPC_HDLC_HEADER_RAW_SIZE);
  }

  bool header_is_null = null_header(rx_buffer);

  // Identity if we had a late header transmission from the secondary.
  if (want_to_receive == false && !header_is_null) {
    // This scenario occurs when the secondary asserted the IRQ right before
    // the primary decides to clock a header and after it checked for the status of the
    // IRQ line. In the head of the primary, the secondary didn't mean to send anything but
    // it did. Correct the situation.
    want_to_receive = true;
  }

  // Identify a false positive. Typically, that would be when the secondary is resetting and the
  // IRQ line is pulled low but we clock nothing.
  if (want_to_transmit == false && header_is_null) {
    return;
  }

  // Compute the size of the next payload we are going to clock
  {
    int rx_payload_size = get_data_size(rx_buffer);

    if (want_to_receive) {
      if (rx_payload_size == -1) {
        rx_header_checksum_error = true;
        rx_payload_size = 0;
      }
      rx_length = (size_t) rx_payload_size;
    } else {
      if (!header_is_null) {
        // The IRQ was not low when we probed it, yet we received something...

        if (rx_payload_size == -1) {
          // The IRQ line was not LOW when we poked it, but we still received a garbage header.
          // This is still a late header transmission, but with what seems to be a corrupted header.
          rx_header_checksum_error = true;

          TRACE_DRIVER_INVALID_HEADER_CHECKSUM();
          TRACE_DRIVER("Header checksum error");

          rx_payload_size = 0;
        } else {
          // The IRQ line was not LOW when we poked it, but we still received a valid header.
          // This is the 'late header transmission' possibility : The secondary pulled the IRQ
          // line low after we read it, and before we pulled the CS low from the header.
          rx_length = (size_t)rx_payload_size;
        }
      }
    }

    // Take the maximum value
    payload_length = (tx_length > rx_length) ? tx_length : rx_length;
  }

  // Wait for the secondary to notify us we can clock the payload
  bool ret = wait_for_irq_assert_or_timeout();

  if (ret == false) { //timed out
    if (secondary_started) {
      BUG("The IRQ it stuck abnormally long in the de-asserted state.");
    } else {
      // The secondary might just not be started
      // Still send to the core at what time the frame was sent.
      {
        struct timespec tx_complete_timestamp;
        clock_gettime(CLOCK_MONOTONIC, &tx_complete_timestamp);
        /* Push write notification to core */
        ssize_t write_retval = write(fd_core_notify, &tx_complete_timestamp, sizeof(tx_complete_timestamp));
        FATAL_SYSCALL_ON(write_retval != sizeof(tx_complete_timestamp));
      }
      // The frame was pulled from the core. The secondary is likely not started. The job is
      // done for now. Wait until the core retries to send a frame.
      return;
    }
  } else { // IRQ got pulled low in time, proceed
    secondary_started = true;
  }

  // Clock the payload
  {
    if ((tx_length == 0) || want_to_transmit == false) {
      local_spi_transfer.tx_buf = (unsigned long) NULL;
    } else {
      local_spi_transfer.tx_buf = (unsigned long) &tx_buffer[SLI_CPC_HDLC_HEADER_RAW_SIZE];
    }

    local_spi_transfer.rx_buf = (unsigned long) &rx_buffer[SLI_CPC_HDLC_HEADER_RAW_SIZE];

    if (rx_header_checksum_error) {
      // If we received a bad header, we will clock the maximum theoretical number of bytes the secondary can
      // send us in order to purge its data
      local_spi_transfer.len = SPI_BUFFER_SIZE - SLI_CPC_HDLC_HEADER_RAW_SIZE;
    } else {
      local_spi_transfer.len = (unsigned int) payload_length;
    }

    int ret = ioctl(spi_dev_descriptor, SPI_IOC_MESSAGE(1), &local_spi_transfer);
    FATAL_ON(ret != (int)local_spi_transfer.len);
  }

  // If a frame has been transmitted, tell the core at which moment it was sent on the wire
  if (want_to_transmit) {
    struct timespec tx_complete_timestamp;
    clock_gettime(CLOCK_MONOTONIC, &tx_complete_timestamp);

    /* Push write notification to core */
    ssize_t write_retval = write(fd_core_notify, &tx_complete_timestamp, sizeof(tx_complete_timestamp));
    FATAL_SYSCALL_ON(write_retval != sizeof(tx_complete_timestamp));
  }

  // Send the received frame to the core (if it was negotiated that we pull one of course)
  if (want_to_receive && !rx_header_checksum_error) {
    ssize_t write_retval;

    // Add the length of the header to the length of the payload to get the total frame length
    rx_length += SLI_CPC_HDLC_HEADER_RAW_SIZE;

    write_retval = write(fd_core, rx_buffer, rx_length);
    FATAL_SYSCALL_ON(write_retval < 0);
    FATAL_SYSCALL_ON((size_t) write_retval != rx_length);

    TRACE_FRAME("Driver : flushed frame to core : ", rx_buffer, rx_length);
  }
}
