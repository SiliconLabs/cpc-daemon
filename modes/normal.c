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

#include "modes/normal.h"
#include "server_core/server_core.h"
#include "driver/driver_uart.h"
#include "driver/driver_spi.h"
#include "misc/config.h"
#include "misc/logging.h"
#include "security/security.h"

extern pthread_t driver_thread;
extern pthread_t server_core_thread;

void main_wait_crash_or_graceful_exit(void);

void run_normal_mode(void)
{
  int fd_socket_driver_core;
  int fd_socket_driver_core_notify;

  // Init the driver
  {
    if (config.bus == UART) {
      driver_thread = driver_uart_init(&fd_socket_driver_core, &fd_socket_driver_core_notify, config.uart_file, config.uart_baudrate, config.uart_hardflow);
    } else if (config.bus == SPI) {
      driver_thread = driver_spi_init(&fd_socket_driver_core,
                                      &fd_socket_driver_core_notify,
                                      config.spi_file,
                                      config.spi_mode,
                                      config.spi_bit_per_word,
                                      config.spi_bitrate,
                                      config.spi_cs_chip,
                                      config.spi_cs_pin,
                                      config.spi_irq_chip,
                                      config.spi_irq_pin,
                                      config.fu_wake_chip,
                                      config.fu_spi_wake_pin);
    } else {
      BUG();
    }
  }

  server_core_thread = server_core_init(fd_socket_driver_core, fd_socket_driver_core_notify, SERVER_CORE_MODE_NORMAL);

#if defined(ENABLE_ENCRYPTION)
  if (config.use_encryption == true) {
    security_post_command(SECURITY_COMMAND_INITIALIZE_SESSION);
  }
#endif

  main_wait_crash_or_graceful_exit();
}
