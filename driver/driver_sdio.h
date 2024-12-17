/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - CPC SDIO driver
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

#ifndef DRIVER_SDIO_H
#define DRIVER_SDIO_H

#include <pthread.h>

// Initialize the sdio driver. Crashes the app if the init fails.
void driver_sdio_init(int *fd_to_core,
                      int *fd_notify_core);

void driver_sdio_kill(void);

#endif // DRIVER_SDIO_H
