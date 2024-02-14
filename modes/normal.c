/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Normal Mode
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

#include <pthread.h>

#include "cpcd/config.h"
#include "cpcd/logging.h"
#include "cpcd/modes.h"
#include "cpcd/security.h"
#include "cpcd/server_core.h"
#include "cpcd/exit.h"

#include "driver/driver_uart.h"
#include "driver/driver_spi.h"
#include "driver/driver_ezsp.h"

void run_normal_mode(void)
{
  int fd_socket_driver_core;
  int fd_socket_driver_core_notify;

  // Init the driver
  {
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
  }

  server_core_init(fd_socket_driver_core, fd_socket_driver_core_notify, SERVER_CORE_MODE_NORMAL);

#if defined(ENABLE_ENCRYPTION)
  if (config.use_encryption == true) {
    security_post_command(SECURITY_COMMAND_INITIALIZE_SESSION);
  }
#endif

  // Block until exit event
  wait_crash_or_graceful_exit();
}

/*
 * @note This function is meant to be called only at startup. If takes ownership
 * of the peripheral file and produces a specific sequence, so would break the
 * communication if reused afterward.
 */
bool is_bootloader_running(void)
{
  static bool secondary_already_probed = false;
  static bool secondary_running_bootloader = false;

  if (secondary_already_probed) {
    return secondary_running_bootloader;
  }

  secondary_already_probed = true;

  if (config.bus == UART) {
    secondary_running_bootloader = driver_uart_is_bootloader_running(config.uart_file,
                                                                     config.uart_baudrate,
                                                                     config.uart_hardflow);
  } else if (config.bus == SPI) {
    secondary_running_bootloader = ezsp_spi_is_bootloader_running(config.spi_file,
                                                                  config.spi_bitrate,
                                                                  config.spi_irq_chip,
                                                                  config.spi_irq_pin);
  } else {
    BUG();
  }

  return secondary_running_bootloader;
}
