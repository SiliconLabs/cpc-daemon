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
#define gpio_t gpio_sysfs_t
typedef struct {
  unsigned int pin;
  int value_fd;
  int irq_fd;
} gpio_t;
#define GPIO_EPOLL_EVENT EPOLLPRI
#else
#include <pthread.h>
#include <gpiod.h>
#define gpio_t gpio_gpiod_t
typedef struct {
  const char *chip_name;
  unsigned int pin;
  struct gpiod_line *line;
  int irq_fd;
} gpio_t;
#define GPIO_EPOLL_EVENT EPOLLIN
#endif

SL_ENUM(gpio_direction_t){
  IN = 0,
  OUT,
  HIGH,
  NO_DIRECTION
};

SL_ENUM(gpio_edge_t){
  FALLING = 0,
  RISING,
  BOTH,
  NO_EDGE
};

int gpio_init(gpio_t *gpio, const char *gpio_chip, unsigned int gpio_pin, gpio_direction_t direction, gpio_edge_t edge);
int gpio_deinit(gpio_t *gpio);
int gpio_get_fd(gpio_t *gpio);
int gpio_clear_irq(gpio_t *gpio);
int gpio_write(gpio_t *gpio, int value);
int gpio_read(gpio_t *gpio);

#endif /* GPIO_H */
