/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) - Socket driver
 *******************************************************************************
 * # License
 * <b>Copyright 2024 Silicon Laboratories Inc. www.silabs.com</b>
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

#ifndef DRIVER_SOCKET_H
#define DRIVER_SOCKET_H

#include <pthread.h>
#include <stdbool.h>

/*
 * Initialize the socket driver.
 */
pthread_t driver_socket_init(int *fd_to_core, int *fd_notify_core);

#endif // DRIVER_SOCKET_H
