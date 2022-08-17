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

#include <sys/epoll.h>
#include <unistd.h>
#include <string.h>

#include "modes/firmware_update.h"
#include "server_core/server_core.h"
#include "driver/driver_uart.h"
#include "driver/driver_spi.h"
#include "driver/driver_xmodem.h"
#include "driver/driver_ezsp.h"
#include "misc/config.h"
#include "misc/gpio.h"
#include "misc/logging.h"
#include "misc/sl_status.h"
#include "misc/sleep.h"
#include "version.h"

#define MAX_EPOLL_EVENTS 10
#define RESET_TIMEOUT_MS 5000

extern pthread_t driver_thread;
extern pthread_t server_core_thread;

extern char *server_core_secondary_app_version;
extern uint8_t server_core_secondary_protocol_version;

static gpio_t wake_gpio;
static gpio_t irq_gpio;
static gpio_t reset_gpio;

static void process_irq(void);

static void assert_reset(void);
static void deassert_reset(void);
static void assert_wake(void);
static void deassert_wake(void);

static void reboot_secondary_with_pins_into_bootloader(void);
static void reboot_secondary_by_cpc(server_core_mode_t mode);

static sl_status_t transfer_firmware(void);

void run_firmware_update(void)
{
  sl_status_t status;

  // If config_fu_connect_to_bootloader is true,
  // we assume the bootloader is already running.
  if (!config_fu_connect_to_bootloader) {
    if (config_fu_recovery_enabled) {
      PRINT_INFO("Requesting reboot into bootloader via Pins...");
      reboot_secondary_with_pins_into_bootloader();
      PRINT_INFO("Secondary is in bootloader");
    } else {
      bool protocol_version_mismatch = true;
      bool application_version_mismatch = true;

      if (!config_fu_enter_bootloader) {
        PRINT_INFO("Requesting versions via CPC...");
        reboot_secondary_by_cpc(SERVER_CORE_MODE_FIRMWARE_RESET);

        protocol_version_mismatch = server_core_secondary_protocol_version != PROTOCOL_VERSION;
        if (protocol_version_mismatch) {
          PRINT_INFO("Secondary Protocol v%d doesn't match the CPCd Protocol v%d", server_core_secondary_protocol_version, PROTOCOL_VERSION);
        }

        if (!server_core_secondary_app_version) {
          PRINT_INFO("Secondary APP version not available, forcing update");
        }

        if (!config_application_version) {
          PRINT_INFO("Firmware file version not provided, forcing update");
        }

        if (server_core_secondary_app_version && config_application_version) {
          application_version_mismatch = strcmp(server_core_secondary_app_version, config_application_version) != 0;
          if (application_version_mismatch) {
            PRINT_INFO("Secondary APP v%s doesn't match the provided APP v%s", server_core_secondary_app_version, config_application_version);
          }
        }
      }

      if (config_fu_enter_bootloader || protocol_version_mismatch || application_version_mismatch) {
        PRINT_INFO("Requesting reboot into bootloader via CPC...");
        reboot_secondary_by_cpc(SERVER_CORE_MODE_FIRMWARE_BOOTLOADER);
        PRINT_INFO("Secondary is in bootloader");
      } else {
        if (config_restart_daemon) {
          PRINT_INFO("Firmware up to date, restarting daemon");
          config_restart_cpcd_without_fw_update_args();
        } else {
          PRINT_INFO("Firmware up to date, exiting daemon");
          sleep_s(2);
          exit(EXIT_SUCCESS);
        }
      }
    }
  }

  // If config_fu_enter_bootloader is true, exit
  // without transferring the firmware.
  if (config_fu_enter_bootloader) {
    sleep_s(2);
    exit(EXIT_SUCCESS);
  }

  status = transfer_firmware();

  if (status == SL_STATUS_OK) {
    if (config_restart_daemon) {
      PRINT_INFO("Firmware upgrade successful, restarting daemon");
      config_restart_cpcd_without_fw_update_args();
    } else {
      PRINT_INFO("Firmware upgrade successful, exiting daemon");
      sleep_s(2);
      exit(EXIT_SUCCESS);
    }
  } else {
    PRINT_INFO("Firmware upgrade failed, exiting daemon");
    sleep_s(2);
    exit(EXIT_FAILURE);
  }
}

static sl_status_t transfer_firmware(void)
{
  sl_status_t status;

  PRINT_INFO("Transferring firmware...");

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
                           config_spi_cs_chip,
                           config_spi_cs_pin,
                           config_spi_irq_chip,
                           config_spi_irq_pin,
                           config_fu_wake_chip,
                           config_fu_spi_wake_pin);
  } else {
    BUG();
  }

  return status;
}

static void reboot_secondary_by_cpc(server_core_mode_t mode)
{
  int fd_socket_driver_core;
  void* join_value;
  int ret;

  // Init the driver
  if (config_bus == UART) {
    driver_thread = driver_uart_init(&fd_socket_driver_core, config_uart_file, config_uart_baudrate, config_uart_hardflow);
  } else if (config_bus == SPI) {
    driver_thread = driver_spi_init(&fd_socket_driver_core,
                                    config_spi_file,
                                    config_spi_mode,
                                    config_spi_bit_per_word,
                                    config_spi_bitrate,
                                    config_spi_cs_chip,
                                    config_spi_cs_pin,
                                    config_spi_irq_chip,
                                    config_spi_irq_pin,
                                    config_fu_wake_chip,
                                    config_fu_spi_wake_pin);
  } else {
    BUG();
  }

  server_core_thread = server_core_init(fd_socket_driver_core, mode);

  ret = pthread_join(server_core_thread, &join_value);
  FATAL_ON(ret != 0);
  FATAL_ON(join_value != 0);

  close(fd_socket_driver_core);
}

static void reboot_secondary_with_pins_into_bootloader(void)
{
  int ret;
  int fds;
  int n;
  struct epoll_event ev;
  struct epoll_event events[MAX_EPOLL_EVENTS] = {};
  static int fd_epoll;

  // Setup WAKE gpio
  FATAL_ON(gpio_init(&wake_gpio, config_fu_wake_chip, config_fu_spi_wake_pin, OUT, NO_EDGE) < 0);
  FATAL_ON(gpio_write(&wake_gpio, 1) < 0);

  // Setup RESET gpio
  FATAL_ON(gpio_init(&reset_gpio, config_fu_reset_chip, config_fu_spi_reset_pin, OUT, NO_EDGE) < 0);
  FATAL_ON(gpio_write(&reset_gpio, 1) < 0);

  if (config_bus == SPI) {
    // Setup IRQ gpio
    FATAL_ON(gpio_init(&irq_gpio, config_spi_irq_chip, config_spi_irq_pin, NO_DIRECTION, FALLING) < 0);

    // Create the epoll set
    fd_epoll = epoll_create1(EPOLL_CLOEXEC);
    FATAL_SYSCALL_ON(fd_epoll < 0);

    // Set up host interrupt
    ev.events = GPIO_EPOLL_EVENT; // Level-triggered read() availability
    ev.data.fd = gpio_get_fd(&irq_gpio);
    ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, gpio_get_fd(&irq_gpio), &ev);
    FATAL_SYSCALL_ON(ret < 0);
  }

  // To reboot into bootloader, assert nWAKE and
  // then reset the device using nRESET. When the
  // bootloader starts (in SPI), it will handshake by asserting
  // nHOST_INT, at which point nWAKE should be deasserted
  assert_wake();
  sleep_us(100);
  assert_reset();
  sleep_us(100);
  deassert_reset();
  sleep_us(100);

  if (config_bus == SPI) {
    // wait for host interrupt
    bool irq = false;
    do {
      fds = epoll_wait(fd_epoll, events, MAX_EPOLL_EVENTS, RESET_TIMEOUT_MS);
      FATAL_SYSCALL_ON(fds == -1);  // epoll failed
      FATAL_ON(fds == 0);           // reset timed out
      for (n = 0; n < fds; n++) {
        if (events[n].data.fd == gpio_get_fd(&irq_gpio)) {
          if (gpio_read(&irq_gpio) == 0) {
            irq = true;
          }
        }
      }
    } while (!irq);
    process_irq();
  } else {
    // uart-xmodem bootloader does not trigger host interrupt
    sleep_s(1);
    deassert_wake();
  }

  gpio_deinit(&wake_gpio);
  gpio_deinit(&reset_gpio);
  if (config_bus == SPI) {
    gpio_deinit(&irq_gpio);
  }

  return;
}

static void assert_reset(void)
{
  FATAL_SYSCALL_ON(gpio_write(&reset_gpio, 0) < 0);
}

static void deassert_reset(void)
{
  FATAL_SYSCALL_ON(gpio_write(&reset_gpio, 1) < 0);
}

static void assert_wake(void)
{
  FATAL_SYSCALL_ON(gpio_write(&wake_gpio, 0) < 0);
}

static void deassert_wake(void)
{
  FATAL_SYSCALL_ON(gpio_write(&wake_gpio, 1) < 0);
}

static void process_irq(void)
{
  gpio_clear_irq(&irq_gpio);

  deassert_wake();
}
