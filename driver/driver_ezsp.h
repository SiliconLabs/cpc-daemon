/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) -  EZSP-SPI driver
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

#ifndef DRIVER_EZSP_H
#define DRIVER_EZSP_H

#define _GNU_SOURCE
#include <pthread.h>

#include <stdbool.h>
#include "misc/gpio.h"
#include "misc/sl_status.h"

sl_status_t send_firmware(const char   *image_file,
                          const char   *device,
                          unsigned int mode,
                          unsigned int bit_per_word,
                          unsigned int speed,
                          unsigned int cs_gpio,
                          unsigned int irq_gpio);

#endif//DRIVER_EZSP_H
