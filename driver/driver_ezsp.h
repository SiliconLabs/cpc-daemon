/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) -  EZSP-SPI driver
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

#ifndef DRIVER_EZSP_H
#define DRIVER_EZSP_H

#define _GNU_SOURCE
#include <pthread.h>

#include <stdbool.h>

#include "cpcd/gpio.h"
#include "cpcd/sl_status.h"

#define START_BTL_FRAME   0xFD
#define END_BTL_FRAME     0xA7
#define SPI_STATUS        0x0B
#define SPI_VERSION       0x0A

sl_status_t send_firmware(const char   *image_file,
                          const char   *device,
                          unsigned int bitrate,
                          const char *irq_gpio_chip,
                          unsigned int irq_gpio_pin);

#endif//DRIVER_EZSP_H
