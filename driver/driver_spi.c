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

#include "server_core/core/crc.h"
#include "server_core/core/hdlc.h"
#include "misc/logging.h"
#include "misc/sleep.h"
#include "driver/driver_spi.h"
#include "driver/driver_kill.h"

#define MAX_EPOLL_EVENTS 5
#define IRQ_LINE_TIMEOUT  10

static int fd_core;
static int fd_core_notify;
static int fd_epoll;
static pthread_t drv_thread;

static cpc_spi_dev_t spi_dev;

static struct spi_ioc_transfer spi_tranfer;

static uint8_t rx_spi_buffer[4096];
static uint8_t tx_spi_buffer[4096];

typedef void (*driver_epoll_callback_t)(void);

static void cs_assert(void);
static void cs_deassert(void);

static bool validate_header(uint8_t *header);
static int get_data_size(uint8_t *header);

static void driver_spi_process_irq(void);
static void driver_spi_clear_and_process_irq(void);
static void driver_spi_process_core(void);
static void* driver_thread_func(void* param);

static void driver_spi_open(const char *device,
                            unsigned int mode,
                            unsigned int bit_per_word,
                            unsigned int speed,
                            const char *cs_gpio_chip,
                            unsigned int cs_gpio_pin,
                            const char *irq_gpio_chip,
                            unsigned int irq_gpio_pin);

static void driver_spi_cleanup(void)
{
  close(spi_dev.spi_dev_descriptor);
  close(fd_core);
  close(fd_core_notify);
  close(fd_epoll);

  gpio_deinit(&spi_dev.cs_gpio);
  gpio_deinit(&spi_dev.irq_gpio);
  gpio_deinit(&spi_dev.wake_gpio);

  TRACE_DRIVER("SPI driver thread cancelled");

  pthread_exit(NULL);
}

pthread_t driver_spi_init(int *fd_to_core,
                          int *fd_notify_core,
                          const char *device,
                          unsigned int mode,
                          unsigned int bit_per_word,
                          unsigned int speed,
                          const char *cs_gpio_chip,
                          unsigned int cs_gpio_pin,
                          const char *irq_gpio_chip,
                          unsigned int irq_gpio_pin)
{
  int fd_sockets[2];
  int fd_sockets_notify[2];
  ssize_t ret;

  driver_spi_open(device,
                  mode,
                  bit_per_word,
                  speed,
                  cs_gpio_chip,
                  cs_gpio_pin,
                  irq_gpio_chip,
                  irq_gpio_pin);

  ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets);
  FATAL_SYSCALL_ON(ret < 0);

  fd_core  = fd_sockets[0];
  *fd_to_core = fd_sockets[1];

  ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets_notify);
  FATAL_SYSCALL_ON(ret < 0);

  fd_core_notify  = fd_sockets_notify[0];
  *fd_notify_core = fd_sockets_notify[1];

  /* Setup epoll */
  {
    struct epoll_event event = {};

    /* Create the epoll set */
    {
      fd_epoll = epoll_create1(EPOLL_CLOEXEC);
      FATAL_SYSCALL_ON(fd_epoll < 0);
    }

    /* Setup the socket to the core */
    {
      event.events = EPOLLIN; /* Level-triggered read() availability */
      event.data.ptr = driver_spi_process_core;
      ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_core, &event);
      FATAL_SYSCALL_ON(ret < 0);
    }

    /* Setup the spi */
    {
      event.events = GPIO_EPOLL_EVENT; /* Level-triggered read() availability */
      event.data.ptr = driver_spi_clear_and_process_irq;
      ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, gpio_get_fd(&spi_dev.irq_gpio), &event);
      FATAL_SYSCALL_ON(ret < 0);
    }

    /* Setup the kill file descriptor */
    {
      int eventfd_kill = driver_kill_init();
      event.events = EPOLLIN; /* Level-triggered read() availability */
      event.data.ptr = driver_spi_cleanup;
      ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, eventfd_kill, &event);
      FATAL_SYSCALL_ON(ret < 0);
    }
  }

  /* create driver thread */
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
  struct epoll_event events[MAX_EPOLL_EVENTS] = {};
  int event_count;

  TRACE_DRIVER("Thread start");

  /*
   * There's a slight behaviour difference when using sysfs or gpiod to
   * control the GPIO: the initial interrupt is reported by the former but
   * not by the latter. As a generic workaround, always try to fetch data
   * from the secondary when the thread spawns.
   */
  driver_spi_process_irq();

  while (1) {
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

  gpio_deinit(&spi_dev.cs_gpio);
  gpio_deinit(&spi_dev.irq_gpio);
  gpio_deinit(&spi_dev.wake_gpio);

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

static void cs_assert(void)
{
  int ret = 0;

  ret = gpio_write(&spi_dev.cs_gpio, 0);

  FATAL_SYSCALL_ON(ret < 0);
}

static void cs_deassert(void)
{
  int ret = 0;

  ret = gpio_write(&spi_dev.cs_gpio, 1);

  FATAL_SYSCALL_ON(ret < 0);
}

static void driver_spi_open(const char *device,
                            unsigned int mode,
                            unsigned int bit_per_word,
                            unsigned int speed,
                            const char *cs_gpio_chip,
                            unsigned int cs_gpio_pin,
                            const char *irq_gpio_chip,
                            unsigned int irq_gpio_pin)
{
  int ret = 0;
  int fd;

  mode |= SPI_NO_CS;

  memset(&spi_tranfer, 0, sizeof(struct spi_ioc_transfer));

  // SPIDEV0: MOSI (GPIO10); MISO (GPIO9); SCLK (GPIO11); RX_IRQ (GPIO23); CS (GPIO24)
  fd = open(device, O_RDWR | O_CLOEXEC);
  FATAL_SYSCALL_ON(fd < 0);

  ret = ioctl(fd, SPI_IOC_WR_MODE, &mode);
  FATAL_SYSCALL_ON(ret < 0);

  ret = ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bit_per_word);
  FATAL_SYSCALL_ON(ret < 0);

  spi_tranfer.bits_per_word = (uint8_t)bit_per_word;

  ret = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
  FATAL_SYSCALL_ON(ret < 0);

  spi_tranfer.speed_hz = speed;

  spi_tranfer.rx_buf = (unsigned long)rx_spi_buffer;
  spi_tranfer.tx_buf = (unsigned long)tx_spi_buffer;

  spi_dev.spi_dev_descriptor = fd;

  // Setup CS gpio
  FATAL_ON(gpio_init(&spi_dev.cs_gpio, cs_gpio_chip, cs_gpio_pin, OUT, NO_EDGE) < 0);
  FATAL_ON(gpio_write(&spi_dev.cs_gpio, 1u) < 0);

  // Setup IRQ gpio
  FATAL_ON(gpio_init(&spi_dev.irq_gpio, irq_gpio_chip, irq_gpio_pin, IN, FALLING) < 0);
}

static void driver_spi_process_irq(void)
{
  int ret = 0;
  int payload_size = 0;
  size_t write_size = 0;
  uint8_t rx_buffer[4096];
  ssize_t write_retval;
  int timeout = IRQ_LINE_TIMEOUT;
  int error_timeout = 4096;

  if (gpio_read(&spi_dev.irq_gpio) == 0) {
    cs_assert();
    sleep_ms(1);

    if (gpio_read(&spi_dev.irq_gpio) != 0u) {
      cs_deassert();
      return;
    }

    spi_tranfer.len = SLI_CPC_HDLC_HEADER_RAW_SIZE;

    ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_tranfer);
    FATAL_ON(ret != SLI_CPC_HDLC_HEADER_RAW_SIZE);

    memcpy(rx_buffer, (uint8_t*)(long)spi_tranfer.rx_buf, SLI_CPC_HDLC_HEADER_RAW_SIZE);

    payload_size = get_data_size((uint8_t *)(long)spi_tranfer.rx_buf);
    if (payload_size == -1) {
      spi_tranfer.len = 1u;

      while ((gpio_read(&spi_dev.irq_gpio) == 0u)
             && (error_timeout > 0)) {
        ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_tranfer);
        FATAL_ON(ret != 1);
        error_timeout--;
      }

      cs_deassert();

      sleep_ms(1);

      TRACE_FRAME("Driver : Invalid header contain: ", rx_buffer, (size_t)SLI_CPC_HDLC_HEADER_RAW_SIZE);
      TRACE_DRIVER("Invalid header");

      return;
    }

    if (payload_size > 0) {
      spi_tranfer.len = (uint32_t)payload_size;
      ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_tranfer);
      FATAL_ON(ret != payload_size);
      memcpy(&rx_buffer[SLI_CPC_HDLC_HEADER_RAW_SIZE], (uint8_t*)(long)spi_tranfer.rx_buf, (uint32_t)payload_size);
      write_size = (uint32_t)payload_size + SLI_CPC_HDLC_HEADER_RAW_SIZE;
    } else if (payload_size == 0) {
      write_size = SLI_CPC_HDLC_HEADER_RAW_SIZE;
    }

    // Wait for NCP to response
    while ((gpio_read(&spi_dev.irq_gpio) != 1)
           && timeout > 0) {
      sleep_us(100);
      timeout--;
    }

    if (timeout == 0) {
      FATAL("Secondary IRQ line is busy !!!!");
    }

    cs_deassert();

    write_retval = write(fd_core, rx_buffer, write_size);
    FATAL_SYSCALL_ON(write_retval < 0);

    sleep_ms(1);

    TRACE_FRAME("Driver : flushed frame to core : ", rx_buffer, (size_t)write_retval);
  }
}

static void driver_spi_clear_and_process_irq(void)
{
  gpio_clear_irq(&spi_dev.irq_gpio);

  driver_spi_process_irq();
}

static void driver_spi_process_core(void)
{
  uint8_t buffer[4096];
  ssize_t read_retval;
  int ret;

  cs_assert();

  sleep_ms(1);

  if (gpio_read(&spi_dev.irq_gpio) == 0) {
    return;
  }

  read_retval = read(fd_core, buffer, sizeof(buffer));
  FATAL_SYSCALL_ON(read_retval < 0);

  memcpy((uint8_t*)(long)spi_tranfer.tx_buf, buffer, (uint32_t)read_retval);

  spi_tranfer.len = (uint32_t)read_retval;

  ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_tranfer);
  FATAL_SYSCALL_ON(ret < 0);

  cs_deassert();

  struct timespec tx_complete_timestamp;
  clock_gettime(CLOCK_MONOTONIC, &tx_complete_timestamp);

  /* Push write notification to core */
  ssize_t write_retval = write(fd_core_notify, &tx_complete_timestamp, sizeof(tx_complete_timestamp));
  FATAL_SYSCALL_ON(write_retval != sizeof(tx_complete_timestamp));

  sleep_ms(1);

  TRACE_FRAME("Driver : flushed frame to SPI : ", buffer, (size_t)read_retval);
}
