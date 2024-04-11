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

sl_status_t ezsp_spi_firmware_upgrade(const char   *image_file,
                                      const char   *device,
                                      unsigned int bitrate,
                                      const char *irq_gpio_chip,
                                      unsigned int irq_gpio_pin);

bool ezsp_spi_is_bootloader_running(const char *device,
                                    unsigned int bitrate,
                                    const char *irq_gpio_chip,
                                    unsigned int irq_gpio_pin);

#endif // DRIVER_EZSP_H
