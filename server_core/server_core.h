/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Server core
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

#ifndef SERVER_CORE_H
#define SERVER_CORE_H

#include <stdint.h>
#include <pthread.h>

uint32_t server_core_get_secondary_rx_capability(void);
pthread_t server_core_init(int fd_socket_driver_core);

#endif //SERVER_CORE_H
