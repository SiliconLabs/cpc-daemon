/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Main
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

#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>

#include "server_core.h"
#include "driver_uart.h"
#include "driver_spi.h"
#include "log.h"
#include "tracing/tracing.h"
#include "config.h"
#include "epoll.h"

pthread_t driver_thread;
pthread_t server_core_thread;

/* Global copy of argv to be able to restart the daemon with the same arguments */
char **argv_g;

int main(int argc, char *argv[])
{
  int fd_socket_driver_core;
  int ret;
  void* join_value;

  argv_g = argv;

  ret = pthread_setname_np(pthread_self(), "main");
  FATAL_ON(ret != 0);

  config_init(argc, argv);

  tracing_init();

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
      return 1;
    }
  }

  server_core_thread = server_core_init(fd_socket_driver_core);

  pthread_join(driver_thread, &join_value);
  pthread_join(server_core_thread, &join_value);

  TRACE_MAIN("Init complete");

  return 0;
}
