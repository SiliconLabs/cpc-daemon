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
#include "misc/gpio.h"
#include "misc/sl_status.h"

sl_status_t send_firmware(const char   *image_file,
                          const char   *device,
                          unsigned int mode,
                          unsigned int bit_per_word,
                          unsigned int speed,
                          const char *cs_gpio_chip,
                          unsigned int cs_gpio_pin,
                          const char *irq_gpio_chip,
                          unsigned int irq_gpio_pin);

#endif//DRIVER_EZSP_H
