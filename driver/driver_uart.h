/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) - UART driver
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

#ifndef DRIVER_UART_H
#define DRIVER_UART_H

#include <pthread.h>
#include <stdbool.h>

/*
 * Initialize the uart driver. Crashes the app if the init fails.
 * Returns the file descriptor of the paired socket to the driver
 * to use in a select() call.
 */
void driver_uart_init(int *fd_to_core, int *fd_notify_core, const char *device, unsigned int baudrate, bool hardflow);

void driver_uart_kill(void);

int driver_uart_open(const char *device, unsigned int baudrate, bool hardflow);

void driver_uart_assert_rts(bool assert);

void driver_uart_print_overruns(void);

#endif // DRIVER_UART_H
