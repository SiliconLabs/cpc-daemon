/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Binding Mode
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

#include <pthread.h>

#include "modes/binding.h"
#include "server_core/server_core.h"
#include "security/security.h"
#include "driver/driver_spi.h"
#include "driver/driver_uart.h"
#include "misc/config.h"
#include "misc/logging.h"

extern pthread_t driver_thread;
extern pthread_t server_core_thread;

void main_wait_crash_or_gracefull_exit(void);

void run_binding_mode(void)
{
  int fd_socket_driver_core;

#if !defined(ENABLE_ENCRYPTION)
  FATAL("Tried to run binding mode with daemon compiled with encryption disabled");
#endif

  if (config_use_encryption == false) {
    FATAL("Tried to run binding mode with encryption disabled");
  }

  // Init the driver
  {
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
  }

  server_core_thread = server_core_init(fd_socket_driver_core, false);

  switch (config_operation_mode) {
    case MODE_BINDING_PLAIN_TEXT:
      security_post_command(SECURITY_COMMAND_PLAIN_TEXT_BINDING);
      break;

    case MODE_BINDING_ECDH:
      security_post_command(SECURITY_COMMAND_ECDH_BINDING);
      break;

    case MODE_BINDING_UNBIND:
      security_post_command(SECURITY_COMMAND_UNBIND);
      break;

    default:
      FATAL("Unsupported operation mode");
  }

  main_wait_crash_or_gracefull_exit();
}
