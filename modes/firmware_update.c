/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Firmware Update Mode
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

#include "config.h"

#include <sys/epoll.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "cpcd/config.h"
#include "cpcd/gpio.h"
#include "cpcd/logging.h"
#include "cpcd/modes.h"
#include "cpcd/server_core.h"
#include "cpcd/sl_status.h"
#include "cpcd/sleep.h"

#include "server_core/system_endpoint/system.h"
#include "driver/driver_uart.h"
#include "driver/driver_spi.h"
#include "driver/driver_xmodem.h"
#include "driver/driver_ezsp.h"

#define RESET_TIMEOUT_MS 500

extern char *server_core_secondary_app_version;
extern uint8_t server_core_secondary_protocol_version;
extern sl_cpc_bootloader_t server_core_secondary_bootloader_type;

static void reboot_secondary_with_pins_into_bootloader(void);
static void reboot_secondary_by_cpc(server_core_mode_t mode);

static sl_status_t transfer_firmware(void);

void run_firmware_update(void)
{
  sl_status_t status;
  bool secondary_already_running_bootloader = is_bootloader_running();

  if (config.fwu_enter_bootloader && secondary_already_running_bootloader) {
    PRINT_INFO("Invoking CPCd with -e option places the secondary in bootloader mode, but the bootloader is already running. Nothing to be done.");

    config_exit_cpcd(EXIT_SUCCESS);
  }

  if (secondary_already_running_bootloader) {
    PRINT_INFO("Performing a firmware upgrade while the bootloader is already running, skipping placing the secondary in bootloader mode");
  } else if (config.fwu_connect_to_bootloader) {
    PRINT_INFO("Performing a firmware upgrade while assuming the bootloader is already running, skipping placing the secondary in bootloader mode");
  } else {
    // Placing the secondary in bootloader monde :

    if (config.fwu_recovery_pins_enabled) {
      PRINT_INFO("Requesting reboot into bootloader via Pins...");
      reboot_secondary_with_pins_into_bootloader();
      PRINT_INFO("Secondary is in bootloader");
    } else {
      bool protocol_version_mismatch = true;
      bool application_version_mismatch = true;

      if (!config.fwu_enter_bootloader) {
        PRINT_INFO("Requesting versions via CPC...");
        reboot_secondary_by_cpc(SERVER_CORE_MODE_FIRMWARE_RESET);

        protocol_version_mismatch = server_core_secondary_protocol_version != PROTOCOL_VERSION;
        if (protocol_version_mismatch) {
          PRINT_INFO("Secondary Protocol v%d doesn't match the CPCd Protocol v%d", server_core_secondary_protocol_version, PROTOCOL_VERSION);
        }

        if (!server_core_secondary_app_version) {
          PRINT_INFO("Secondary APP version not available, forcing update");
        }

        if (!config.application_version_validation) {
          PRINT_INFO("Firmware file version not provided, forcing update");
        }

        if (server_core_secondary_app_version && config.application_version_validation) {
          application_version_mismatch = strcmp(server_core_secondary_app_version, config.application_version_validation) != 0;
          if (application_version_mismatch) {
            PRINT_INFO("Secondary APP v%s doesn't match the provided APP v%s", server_core_secondary_app_version, config.application_version_validation);
          }
        }

        if (server_core_secondary_bootloader_type != SL_CPC_BOOTLOADER_EMBER_APPLICATION
            && server_core_secondary_bootloader_type != SL_CPC_BOOTLOADER_EMBER_STANDALONE
            && server_core_secondary_bootloader_type != SL_CPC_BOOTLOADER_GECKO) {
          if (server_core_secondary_bootloader_type == SL_CPC_BOOTLOADER_NONE) {
            FATAL("Secondary has no Bootloader");
          }
          WARN("Unsupported bootloader type, update might fail unexpectedly");
        }
      }

      if (config.fwu_enter_bootloader || protocol_version_mismatch || application_version_mismatch) {
        PRINT_INFO("Requesting reboot into bootloader via CPC...");
        reboot_secondary_by_cpc(SERVER_CORE_MODE_FIRMWARE_BOOTLOADER);
      } else {
        if (config.restart_cpcd) {
          PRINT_INFO("Firmware up to date, restarting daemon");
          config_restart_cpcd_without_fw_update_args();
        } else {
          PRINT_INFO("Firmware up to date, exiting daemon");
          config_exit_cpcd(EXIT_SUCCESS);
        }
      }
    }
  }

  // If fwu_enter_bootloader is true, exit
  // without transferring the firmware.
  if (config.fwu_enter_bootloader) {
    config_exit_cpcd(EXIT_SUCCESS);
  }

  status = transfer_firmware();

  if (status == SL_STATUS_OK) {
    PRINT_INFO("Firmware upgrade successful");
    if (config.restart_cpcd) {
      config_restart_cpcd_without_fw_update_args();
    } else {
      config_exit_cpcd(EXIT_SUCCESS);
    }
  } else {
    PRINT_INFO("Firmware upgrade failed");
    config_exit_cpcd(EXIT_FAILURE);
  }
}

static sl_status_t transfer_firmware(void)
{
  sl_status_t status;

  PRINT_INFO("Transferring firmware...");

  if (config.bus == UART) {
    status = xmodem_uart_firmware_upgrade(config.fwu_file,
                                          config.uart_file,
                                          config.uart_baudrate,
                                          config.uart_hardflow);
  } else if (config.bus == SPI) {
    status = ezsp_spi_firmware_upgrade(config.fwu_file,
                                       config.spi_file,
                                       config.spi_bitrate,
                                       config.spi_irq_chip,
                                       config.spi_irq_pin);
  } else {
    BUG();
  }

  return status;
}

static void reboot_secondary_by_cpc(server_core_mode_t mode)
{
  int fd_socket_driver_core;
  int fd_socket_driver_core_notify;

  // Init the driver
  if (config.bus == UART) {
    driver_uart_init(&fd_socket_driver_core,
                     &fd_socket_driver_core_notify,
                     config.uart_file,
                     config.uart_baudrate,
                     config.uart_hardflow);
  } else if (config.bus == SPI) {
    driver_spi_init(&fd_socket_driver_core,
                    &fd_socket_driver_core_notify,
                    config.spi_file,
                    config.spi_bitrate,
                    config.spi_irq_chip,
                    config.spi_irq_pin);
  } else {
    BUG();
  }

  server_core_init(fd_socket_driver_core, fd_socket_driver_core_notify, mode);

  server_core_wait();

  close(fd_socket_driver_core);
  close(fd_socket_driver_core_notify);
}

static void reboot_secondary_with_pins_into_bootloader(void)
{
  gpio_t wake_gpio;
  gpio_t irq_gpio;
  gpio_t reset_gpio;
  int ret;
  struct epoll_event ev;
  static int fd_epoll;
  bus_t bus = config.bus;

  reset_gpio = gpio_init(config.fwu_reset_chip, (unsigned int)config.fwu_spi_reset_pin, GPIO_DIRECTION_OUT, GPIO_EDGE_NO_EDGE);
  wake_gpio  = gpio_init(config.fwu_wake_chip, (unsigned int)config.fwu_spi_wake_pin, GPIO_DIRECTION_OUT, GPIO_EDGE_NO_EDGE);

  if (bus == SPI) {
    irq_gpio = gpio_init(config.spi_irq_chip, config.spi_irq_pin, GPIO_DIRECTION_IN, GPIO_EDGE_FALLING);

    // Create the epoll set
    fd_epoll = epoll_create1(EPOLL_CLOEXEC);
    FATAL_SYSCALL_ON(fd_epoll < 0);

    // Set up host interrupt
    ev.events = GPIO_EPOLL_EVENT; // Level-triggered read() availability
    ev.data.fd = gpio_get_epoll_fd(irq_gpio);
    ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, gpio_get_epoll_fd(irq_gpio), &ev);
    FATAL_SYSCALL_ON(ret < 0);
  }

  // Assert reset and wake
  gpio_write(reset_gpio, GPIO_VALUE_LOW);
  gpio_write(wake_gpio, GPIO_VALUE_LOW);

  // Make sure the reset signal is asserted for long enough
  sleep_us(100);

  // De-assert reset to let the secondary boot, but keep the wake pin asserted
  // so when the bootloader checks the wake pin, instead of booting the app it
  // will stay in bootloader mode
  gpio_write(reset_gpio, GPIO_VALUE_HIGH);

  if (bus == SPI) {
    // Make sure the falling-edge caused by the chip entering reset is cleared
    gpio_clear_irq(irq_gpio);

    // Wait for the low-high-low transition on IRQ meaning the bootloader is alive
    while (1) {
      struct epoll_event event;

      // The bootloader takes slightly under 40ms to boot up and read the wake pin
      int event_count = epoll_wait(fd_epoll,
                                   &event,
                                   1,
                                   RESET_TIMEOUT_MS);

      if (event_count == -1 && errno == EINTR) {
        continue;
      }

      FATAL_SYSCALL_ON(event_count == -1);
      BUG_ON(event_count > 1);
      if (event_count == 0) {
        FATAL("While using the bootloader recovery pins to reset the secondary, "
              "no following transition on the IRQ pin was detected in time. "
              "This means there might be a problem with the pins or the "
              "bootloader (or absence of)");
      }

      break;
    }

    // The bootloader is alive, de-assert the wake pin
    gpio_write(wake_gpio, GPIO_VALUE_HIGH);
  } else {
    // With the UART bootloader, there is no way to know when the bootloader
    // started and read the value of the wake pin, just wait and assume
    sleep_us(RESET_TIMEOUT_MS * 1000);
    gpio_write(wake_gpio, GPIO_VALUE_HIGH);
  }

  gpio_deinit(wake_gpio);
  gpio_deinit(reset_gpio);
  if (bus == SPI) {
    gpio_deinit(irq_gpio);
  }

  return;
}
