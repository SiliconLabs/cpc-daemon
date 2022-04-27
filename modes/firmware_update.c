/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Firmware Update Mode
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

#include "modes/firmware_update.h"
#include "server_core/server_core.h"
#include "driver/driver_uart.h"
#include "driver/driver_spi.h"
#include "driver/driver_xmodem.h"
#include "driver/driver_ezsp.h"
#include "misc/config.h"
#include "misc/logging.h"
#include "misc/gpio.h"
#include "misc/sl_status.h"

#include <sys/epoll.h>
#include <unistd.h>

#define MAX_EPOLL_EVENTS 10
#define RESET_TIMEOUT_MS 5000

extern pthread_t driver_thread;
extern pthread_t server_core_thread;

static gpio_t wake_gpio;
static gpio_t irq_gpio;
static gpio_t reset_gpio;

static void clear_rx_interrupt(gpio_t gpio);

static void assert_reset(void);
static void deassert_reset(void);
static void assert_wake(void);
static void deassert_wake(void);
static void reboot_secondary_with_pins(void);
static void process_irq(void);

void run_firmware_update(void)
{
  int fd_socket_driver_core;
  void* join_value;
  int ret;
  sl_status_t status;

  if (config_recovery_enabled == true) {
    // pins are available to force a reboot into bootloader
    PRINT_INFO("Using pins to reboot into bootloader...");
    reboot_secondary_with_pins();
  } else {
    // request reboot to bootloader via CPC
    // Init the driver
    if (config_bus == UART) {
      driver_thread = driver_uart_init(&fd_socket_driver_core, config_uart_file, config_uart_baudrate, config_uart_hardflow);
    } else if (config_bus == SPI) {
      driver_thread = driver_spi_init(&fd_socket_driver_core,
                                      config_spi_file,
                                      config_spi_mode,
                                      config_spi_bit_per_word,
                                      config_spi_bitrate,
                                      config_spi_cs_pin,
                                      config_spi_irq_pin);
    } else {
      BUG();
    }
    server_core_thread = server_core_init(fd_socket_driver_core, true);

    ret = pthread_join(server_core_thread, &join_value);
    FATAL_ON(ret != 0);
    FATAL_ON(join_value != 0);

    PRINT_INFO("Starting firmware upgrade");

    close(fd_socket_driver_core);
  }

  PRINT_INFO("Secondary is in bootloader, sending firmware");
  // Init the bootloader communication driver
  if (config_bus == UART) {
    status = xmodem_send(config_fu_file,
                         config_uart_file,
                         config_uart_baudrate,
                         config_uart_hardflow);
  } else if (config_bus == SPI) {
    status = send_firmware(config_fu_file,
                           config_spi_file,
                           config_spi_mode,
                           config_spi_bit_per_word,
                           config_spi_bitrate,
                           config_spi_cs_pin,
                           config_spi_irq_pin);
  } else {
    BUG();
  }

  if (status == SL_STATUS_OK) {
    PRINT_INFO("Firmware upgrade successful. Exiting, restart CPCd without -f option.");
    exit(EXIT_SUCCESS);
  } else {
    PRINT_INFO("Firmware upgrade failed.");
    exit(EXIT_FAILURE);
  }
}

static void reboot_secondary_with_pins(void)
{
  int ret;
  int fds;
  int n;
  struct epoll_event ev;
  struct epoll_event events[MAX_EPOLL_EVENTS] = {};
  static int fd_epoll;

  // Setup WAKE gpio
  FATAL_ON(gpio_init(&wake_gpio, config_wake_pin) < 0);
  FATAL_ON(gpio_direction(wake_gpio, OUT) < 0);
  FATAL_ON(gpio_write(wake_gpio, 1) < 0);

  // Setup RESET gpio
  FATAL_ON(gpio_init(&reset_gpio, config_reset_pin) < 0);
  FATAL_ON(gpio_direction(reset_gpio, OUT) < 0);
  FATAL_ON(gpio_write(reset_gpio, 1) < 0);

  if (config_bus == SPI) {
    // Setup IRQ gpio
    FATAL_ON(gpio_init(&irq_gpio, config_spi_irq_pin) < 0);
    FATAL_ON(gpio_direction(irq_gpio, IN) < 0);
    FATAL_ON(gpio_setedge(irq_gpio, FALLING) < 0);

    // Create the epoll set
    fd_epoll = epoll_create1(EPOLL_CLOEXEC);
    FATAL_SYSCALL_ON(fd_epoll < 0);

    // Set up host interrupt
    ev.events = EPOLLPRI; // Level-triggered read() availability
    ev.data.fd = irq_gpio.irq_fd;
    ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, irq_gpio.irq_fd, &ev);
    FATAL_SYSCALL_ON(ret < 0);
  }

  // To reboot into bootloader, assert nWAKE and
  // then reset the device using nRESET. When the
  // bootloader starts (in SPI), it will handshake by asserting
  // nHOST_INT, at which point nWAKE should be deasserted
  assert_wake();
  usleep(100);
  assert_reset();
  usleep(100);
  deassert_reset();
  usleep(100);

  if (config_bus == SPI) {
    // wait for host interrupt
    bool irq = false;
    do {
      fds = epoll_wait(fd_epoll, events, MAX_EPOLL_EVENTS, RESET_TIMEOUT_MS);
      FATAL_SYSCALL_ON(fds == -1);  // epoll failed
      FATAL_ON(fds == 0);           // reset timed out
      for (n = 0; n < fds; n++) {
        if (events[n].data.fd == irq_gpio.irq_fd) {
          if (gpio_read(irq_gpio) == 0) {
            irq = true;
          }
        }
      }
    } while (!irq);
    process_irq();
  } else {
    // uart-xmodem bootloader does not trigger host interrupt
    sleep(1);
    deassert_wake();
  }

  gpio_deinit(&wake_gpio);
  gpio_deinit(&reset_gpio);
  if (config_bus == SPI) {
    gpio_deinit(&irq_gpio);
  }

  return;
}

static void clear_rx_interrupt(gpio_t gpio)
{
  char buf[8];

  // Consume interrupt
  lseek(gpio.irq_fd, 0, SEEK_SET);
  read(gpio.irq_fd, buf, sizeof(buf));
}

static void assert_reset(void)
{
  FATAL_SYSCALL_ON(gpio_write(reset_gpio, 0) < 0);
}

static void deassert_reset(void)
{
  FATAL_SYSCALL_ON(gpio_write(reset_gpio, 1) < 0);
}

static void assert_wake(void)
{
  FATAL_SYSCALL_ON(gpio_write(wake_gpio, 0) < 0);
}

static void deassert_wake(void)
{
  FATAL_SYSCALL_ON(gpio_write(wake_gpio, 1) < 0);
}

static void process_irq(void)
{
  clear_rx_interrupt(irq_gpio);

  deassert_wake();
}
