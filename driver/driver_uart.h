/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) - UART driver
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

#ifndef DRIVER_UART_H
#define DRIVER_UART_H

#include <stdbool.h>
#include <pthread.h>

/*
 * Initialize the uart driver. Crashes the app if the init fails.
 * Returns the file descriptor of the paired socket to the driver
 * to use in a select() call.
 */
pthread_t driver_uart_init(int *fd_core_driver, const char *dev_name, unsigned  int bitrate, bool hardflow);

#endif //DRIVER_UART_H
