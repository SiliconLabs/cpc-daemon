/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) -  SPI driver
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

#ifndef DRIVER_SPI_H
#define DRIVER_SPI_H

#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>

#include "cpcd/gpio.h"

#define SPI_BUFFER_SIZE  4096
#define SPI_INITIAL_BITRATE 1000000

/*
 * Initialize the spi driver. Crashes the app if the init fails.
 * Returns the file descriptor of the paired socket to the driver
 * to use in a select() call.
 */
void driver_spi_init(int *fd_to_core,
                     int *fd_notify_core,
                     const char *device,
                     unsigned int speed,
                     const char *irq_gpio_chip,
                     unsigned int irq_gpio_pin);

void driver_spi_kill(void);

#endif // DRIVER_SPI_H
