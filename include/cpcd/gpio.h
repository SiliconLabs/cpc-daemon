/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - GPIO Interface
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

#ifndef GPIO_H
#define GPIO_H

#include "sl_cpc.h"

#ifdef USE_LEGACY_GPIO_SYSFS
typedef struct {
  unsigned int pin;
  int value_fd;
  int irq_fd;
} gpio_sysfs_t;

typedef gpio_sysfs_t* gpio_t;

#define GPIO_EPOLL_EVENT EPOLLPRI

#else
typedef int gpio_t;
#define GPIO_EPOLL_EVENT EPOLLIN
#endif

SL_ENUM(gpio_direction_t){
  GPIO_DIRECTION_IN,
  GPIO_DIRECTION_OUT
};

SL_ENUM(gpio_edge_t){
  GPIO_EDGE_FALLING,
  GPIO_EDGE_RISING,
  GPIO_EDGE_BOTH,
  GPIO_EDGE_NO_EDGE
};

SL_ENUM(gpio_value_t){
  GPIO_VALUE_LOW = 0,
  GPIO_VALUE_HIGH = 1
};

gpio_t gpio_init(const char *gpio_chip, unsigned int gpio_pin, gpio_direction_t direction, gpio_edge_t edge);

void gpio_deinit(gpio_t gpio);

void gpio_write(gpio_t gpio, gpio_value_t value);

gpio_value_t gpio_read(gpio_t gpio);

int gpio_get_epoll_fd(gpio_t gpio);

// Clears a single gpio IRQ event.
void gpio_clear_irq(gpio_t gpio);

#endif // GPIO_H
