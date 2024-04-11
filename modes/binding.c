/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Binding Mode
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

#include "driver/driver_spi.h"
#include "driver/driver_uart.h"

void run_binding_mode(void)
{
  int fd_socket_driver_core;
  int fd_socket_driver_core_notify;

  PRINT_INFO("Note: Please make sure the unbind functionality is implemented for your product. By default, unbinding requests will be refused, refer to CPC documentation for further details.");

#if !defined(ENABLE_ENCRYPTION)
  FATAL("Tried to run binding mode with daemon compiled with encryption disabled");
#endif

  if (config.use_encryption == false) {
    FATAL("Tried to run binding mode with encryption disabled");
  }

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

  switch (config.operation_mode) {
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

  wait_crash_or_graceful_exit();
}
