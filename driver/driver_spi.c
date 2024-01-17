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
#include "driver/driver_ezsp.h"
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

static int get_data_size(uint8_t *header);
static bool wait_for_irq_assert_or_timeout(size_t timeout_us);
static void driver_spi_event_core(void);
static void driver_spi_event_irq(void);
static void driver_spi_transaction(bool initiated_by_irq_line_event);
static void* driver_thread_func(void* param);

static void driver_spi_cleanup(void)
{
  close(spi_dev_descriptor);
  close(fd_core);
  close(fd_core_notify);
  close(fd_epoll);

  gpio_deinit(irq_gpio);

  TRACE_DRIVER("SPI driver thread cancelled");

  pthread_exit(NULL);
}

static void spidev_setup(const char *device, uint32_t speed, const char *irq_gpio_chip, unsigned int irq_gpio_pin)
{
  ssize_t ret;

  spi_dev_descriptor = open(device, O_RDWR | O_CLOEXEC);
  FATAL_SYSCALL_ON(spi_dev_descriptor < 0);

  const uint8_t mode = SPI_MODE_0;
  ret = ioctl(spi_dev_descriptor, SPI_IOC_WR_MODE, &mode);
  FATAL_SYSCALL_ON(ret < 0);

  const uint8_t bit_per_word = 8;
  ret = ioctl(spi_dev_descriptor, SPI_IOC_WR_BITS_PER_WORD, &bit_per_word);
  FATAL_SYSCALL_ON(ret < 0);

  ret = ioctl(spi_dev_descriptor, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
  FATAL_SYSCALL_ON(ret < 0);

  // Setup IRQ gpio
  irq_gpio = gpio_init(irq_gpio_chip, irq_gpio_pin, GPIO_DIRECTION_IN, GPIO_EDGE_FALLING);
}

/***************************************************************************//**
 * @brief
 *   Probes the secondary to see if the bootloader is running
 *
 * The goal of the probe maneuver is to detect if the secondary is currently
 * running the bootloader or not (else the CPC application, or perhaps nothing).
 *
 * There is an important detail to keep in mind : The SPI driver on the secondary
 * is very susceptible to deadlocking if the CPC SPI protocol is not strictly
 * followed. This means that if the secondary is currently running the CPC app and
 * we start sending things (i.e. talking EZSP-bootloader protocol to probe the
 * bootloader) on the SPI bus that do not follow the CPC-SPI protocol, we will
 * make the secondary driver fall out of sync, requiring a reboot.
 *
 * This function therefore sends what is essentially a CPC SPI Header in term
 * of electrical signal - ie 7 bytes - that would not make the CPC SPI driver
 * jam, but that header is also a valid EZSP transaction that the bootloader
 * would recognize as a probe. This way, no matter what the secondary is currently
 * running, it won't brick.
 *
 * @return
 *   true if the bootloader is running, false otherwise
 ******************************************************************************/
bool driver_spi_is_bootloader_running(const char *device,
                                      unsigned int speed,
                                      const char *irq_gpio_chip,
                                      unsigned int irq_gpio_pin)
{
  bool bootloader_alive = false; // The return value
  struct spi_ioc_transfer spi_transfer = { 0 };
  uint8_t rx_buffer[7];
  int ret;

  spidev_setup(device, speed, irq_gpio_chip, irq_gpio_pin);

  // Always go with a conservative value of 1MHz for the probing sequence
  spi_transfer.speed_hz = 1000000;

  // Send the SPI status bootloader command
  // and keep CS asserted at the end of the transfer
  {
    const uint8_t spi_status_tx_buffer[2] = { SPI_STATUS, END_BTL_FRAME };

    spi_transfer.tx_buf = (unsigned long) spi_status_tx_buffer;
    spi_transfer.rx_buf = (unsigned long) &rx_buffer[0];
    spi_transfer.len = sizeof(spi_status_tx_buffer);
    spi_transfer.cs_change = 1; // Keep CS asserted after the transfer per EZSP

    ret = ioctl(spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_transfer);
    FATAL_ON(ret != (int)spi_transfer.len);
  }

  if (gpio_read(irq_gpio) == GPIO_VALUE_HIGH) {
    // If after sending two bytes the IRQ line is high, it ***could*** mean we are talking to the
    // bootloader.
    // In this case, per EZSP, we need to wait until the IRQ line is asserted before clocking the
    // response. The bootlaoder would not take more than 1ms to assert IRQ if its active though.
    // A typical response time is around 600us.
    (void) wait_for_irq_assert_or_timeout(1000);
  } else {
    // If after sending two bytes the IRQ line is still low, it surely means the bootloader
    // is not active since that would break the EZSP protocol. Do no wait and go straight
    // to the completion of clocking the pseudo-header
  }

  // Clock 5 more 0x00 bytes and de-assert CS.
  {
    spi_transfer.tx_buf = (unsigned long) NULL;
    spi_transfer.rx_buf = (unsigned long) &rx_buffer[2];
    spi_transfer.len = 5;
    spi_transfer.cs_change = 0; // De-assert CS after transfer

    ret = ioctl(spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_transfer);
    FATAL_ON(ret != (int)spi_transfer.len);
  }

  // Analyze the receive buffer to see if a valid bootloader response is detected
  {
    // There are 3 possible responses the bootloader could reply to the SPI-Status command
    const uint8_t btl_response_reset_reason[]  = { 0xFF, 0xFF, 0x00, 0x09, END_BTL_FRAME, 0xFF, 0xFF };
    const uint8_t btl_response_spi_status[]    = { 0xFF, 0xFF, 0xC1, END_BTL_FRAME, 0xFF, 0xFF, 0xFF };
    const uint8_t btl_response_spi_status2[]   = { 0xFF, 0xFF, 0xC0, END_BTL_FRAME, 0xFF, 0xFF, 0xFF };

    if (   0 == memcmp(rx_buffer, btl_response_reset_reason, sizeof(btl_response_reset_reason))
           || 0 == memcmp(rx_buffer, btl_response_spi_status, sizeof(btl_response_spi_status))
           || 0 == memcmp(rx_buffer, btl_response_spi_status2, sizeof(btl_response_spi_status2))) {
      // A positive bootloader response has been received. It is safe to return now without
      // purging a CPC payload. Since CPC is not running there is no risk of de-synchronizing the
      // SPI driver.
      bootloader_alive = true;
      goto ret;
    }
  }

  // At this point, we know the bootloader is NOT running.
  // It could still very well be CPC, or nothing.
  // Analyzing the header for a NULL header (i.e. 7 0s) is not a sufficient criteria to know whether CPC
  // is running or not. We cannot take the chance of stopping here and brick the driver,
  // we have to complete this operation as if it was a real CPC frame.

  // Analyze the received buffer to see if it was a CPC header the secondary sent us
  int header_len_field = get_data_size(rx_buffer);

  if (header_len_field < 0) {
    // The header was not a valid CPC header. For the purpose or the procedure, treat it as if the length was 0
    header_len_field = 0;
  }

  // In case CPC is running, per the SPI protocol, wait for IRQ to be asserted
  (void) wait_for_irq_assert_or_timeout(10 * MAXIMUM_REASONABLE_INTERRUPT_LATENCY_US);

  // The secondary, if running CPC, expects the primary to clock out the payload
  {
    uint8_t *zero_buffer;

    // We don't care about the received data
    spi_transfer.rx_buf = (unsigned long) NULL;

    if (header_len_field > 0) {
      // If we did clock a valid CPC header with a payload length that was greater than 0,
      // we need to clock that number of bytes. We don't care about what we transmit nor
      // receive. rx_buf is already NULL, but we cannot set tx_buf to NULL as well, it needs
      // to be a valid buffer. Here we want to send all 0s.
      zero_buffer = calloc(1, (size_t)header_len_field);
      spi_transfer.tx_buf = (unsigned long) zero_buffer;
    } else {
      // Produce the CS empty notch
      spi_transfer.tx_buf = (unsigned long) NULL;
    }

    spi_transfer.len = (unsigned) header_len_field;
    spi_transfer.cs_change = 0;

    ret = ioctl(spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_transfer);
    FATAL_ON(ret != (int)spi_transfer.len);

    if (header_len_field > 0) {
      free(zero_buffer);
    }
  }

  ret:
  close(spi_dev_descriptor);
  gpio_deinit(irq_gpio);

  return bootloader_alive;
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

  spidev_setup(device, speed, irq_gpio_chip, irq_gpio_pin);

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
    struct epoll_event event = { 0 };

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
      ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, gpio_get_epoll_fd(irq_gpio), &event);
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

    // Process the ready file descriptor
    driver_epoll_callback_t callback = (driver_epoll_callback_t) event.data.ptr;
    callback();
  } //while(1)
}

/***************************************************************************//**
 * @brief Extracts the payload size from a HDLC header
 *
 * @return
 *   The extracted payload size, or -1 if the header is invalid
 ******************************************************************************/
static int get_data_size(uint8_t *header)
{
  if (header[SLI_CPC_HDLC_FLAG_POS] != SLI_CPC_HDLC_FLAG_VAL) {
    return -1;
  }

  if (sli_cpc_get_crc_sw(header, SLI_CPC_HDLC_HEADER_SIZE) != hdlc_get_hcs(header)) {
    TRACE_DRIVER_INVALID_HEADER_CHECKSUM();
    return -1;
  }

  return (int) hdlc_get_length(header);
}

static void driver_spi_event_core(void)
{
  int length;

  ssize_t ret = ioctl(fd_core, FIONREAD, &length);
  FATAL_SYSCALL_ON(ret < 0);

  // Check if the event is about the client closing the connection
  if (length == 0) {
    // The core socket file descriptor was closed. The daemon is being torn down, kill this thread right now
    driver_spi_cleanup();
  }

  // false == transaction initiated by core event
  driver_spi_transaction(false);
}

static void driver_spi_event_irq(void)
{
  // true == transaction initiated by IRQ line event
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
static bool wait_for_irq_assert_or_timeout(size_t timeout_us)
{
  //TODO CPC-649 Rewrite this method

  // In 99.99% of the cases, the secondary executed its header interrupt and lowered IRQ before
  // the host even returns from the SPI ioctl transfer call. Try executing the minimal amount of logic
  // path first
  if (gpio_read(irq_gpio) == GPIO_VALUE_LOW) {
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
  while (gpio_read(irq_gpio) == GPIO_VALUE_HIGH) {
    struct timespec now_time;
    clock_gettime(CLOCK_MONOTONIC, &now_time);

    // Timeout on 10 * MAXIMUM_REASONABLE_INTERRUPT_LATENCY_US
    if (t2_minus_t1_us(&now_time, &start_time) > (long) timeout_us) {
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

static void driver_spi_transaction(bool initiated_by_irq_line_event)
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

  TRACE_DRIVER("Init of a transaction caused by the %s", initiated_by_irq_line_event ? "IRQ line" : "core");

  if (initiated_by_irq_line_event) {
    gpio_clear_irq(irq_gpio);
  }

  // Check if the secondary is signaling it wants to send a frame.
  if (gpio_read(irq_gpio) == GPIO_VALUE_LOW) {
    want_to_receive = true;
    TRACE_DRIVER("Secondary signaled a frame to send");

    if (initiated_by_irq_line_event == false) {
      // This was a transaction initiated by a message from the core.
      // Even if the core initiated the transaction, we still checked the IRQ line
      // because its possible the secondary also wants to send a frame at the same time
      // but its the core file descriptor that unblocked epoll first.
      // Here, reading the IRQ line showed that the secondary has a message to send as well.
      // That means a falling edge event will have been registered in the background.
      // Acknowledge it now otherwise it will trigger a future epoll event for a transaction
      // from the secondary that we will have done [in this transaction].
      gpio_clear_irq(irq_gpio);
    }
  }

  // Check if the host has something to send
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

      TRACE_DRIVER("Primary has a frame to send");
    }
  }

  if (want_to_receive  == false && want_to_transmit == false) {
    // False positive. infrequent but not impossible that this happens with the
    // IRQ rising edge of the header happening when CS of the header falls
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

    TRACE_FRAME("Driver : Clocked in this header : ", rx_buffer, SLI_CPC_HDLC_HEADER_RAW_SIZE);
  }

  bool header_is_null = null_header(rx_buffer);

  // Identity if we had a late header transmission from the secondary.
  if (want_to_receive == false && header_is_null == false) {
    // This scenario occurs when the secondary asserted the IRQ riiiight after
    // we double checked the IRQ line above and riiiight before clocking the header.
    // Clocking a non-null header is the symptom of that.
    want_to_receive = true;

    // It also means, like in the case of the IRQ double check above, that a IRQ
    // line event will have been registered in the background. Acknowledge it now
    // otherwise the event will trigger epoll for the event we are about to take
    // care of now
    gpio_clear_irq(irq_gpio);

    TRACE_DRIVER("Late header");
  }

  // Identify a false positive with IRQ low at the beginning of the transaction
  if (want_to_transmit == false && header_is_null) {
    static size_t false_positive_count = 0;

    switch (++false_positive_count) {
      case 1:
        TRACE_DRIVER("First false positive : Happens when the secondary reboot during the reset sequence");
        break;
      case 2:
        TRACE_DRIVER("Second false positive : Happens if the secondary performs a spurious reset. Expect receiving a reset reason soon");
        break;
      default:
        WARN("False positive #%zu, something is going on", false_positive_count);
        break;
    }
    return;
  }

  // Compute the size of the next payload we are going to clock
  {
    if (want_to_receive) {
      int rx_payload_size = get_data_size(rx_buffer);

      if (rx_payload_size == -1) {
        rx_header_checksum_error = true;
        rx_length = 0;

        TRACE_DRIVER_INVALID_HEADER_CHECKSUM();
        TRACE_DRIVER("Header checksum error");
      } else {
        rx_length = (size_t) rx_payload_size;
      }
    } else {
      rx_length = 0;
    }

    // The number of payload bytes to clock needs to be the maximum between
    // the number of bytes the host wants and the secondary want to send
    payload_length = (tx_length > rx_length) ? tx_length : rx_length;
  }

  // Wait for the secondary to notify us we can clock the payload
  bool ret = wait_for_irq_assert_or_timeout(10 * MAXIMUM_REASONABLE_INTERRUPT_LATENCY_US);

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

    // There has been a high->low transition on the IRQ line for the sync mechanism.
    // Clear the falling-edge event that have been registered in order to avoid initiating a future
    // transaction on that edge event that was not about a new packet from the secondary
    gpio_clear_irq(irq_gpio);
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

    TRACE_FRAME("Driver : Sent frame to core : ", rx_buffer, rx_length);
  }
}
