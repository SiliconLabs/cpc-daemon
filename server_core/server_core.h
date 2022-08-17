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

#define _GNU_SOURCE
#include <pthread.h>

#include <stdint.h>
#include <stdbool.h>

typedef enum {
  SERVER_CORE_MODE_NORMAL,
  SERVER_CORE_MODE_FIRMWARE_BOOTLOADER,
  SERVER_CORE_MODE_FIRMWARE_RESET
} server_core_mode_t;

uint32_t server_core_get_secondary_rx_capability(void);

pthread_t server_core_init(int fd_socket_driver_core, server_core_mode_t mode);

void server_core_kill_signal(void);

bool server_core_reset_sequence_in_progress(void);

#endif //SERVER_CORE_H
