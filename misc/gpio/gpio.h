/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - GPIO Interface
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

#ifndef GPIO_H
#define GPIO_H

#include <stdint.h>
#include "sl_enum.h"

SL_ENUM(gpio_direction_t){
  IN = 0,
  OUT,
  HIGH
};

SL_ENUM(gpio_edge_t){
  FALLING = 0,
  RISING,
  BOTH
};

typedef struct gpio{
  int value_fd;
  int irq_fd;
  unsigned int pin;
} gpio_t;

int gpio_init(gpio_t *gpio, unsigned int pin);
int gpio_deinit(gpio_t *gpio);
int gpio_direction(gpio_t gpio, gpio_direction_t direction);
int gpio_setedge(gpio_t gpio, gpio_edge_t edge);
int gpio_write(gpio_t gpio, int value);
int gpio_read(gpio_t gpio);

#endif /* GPIO_H */
