/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - GPIO Gpiod Interface
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
#define _GNU_SOURCE

#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cpcd/gpio.h"
#include "cpcd/logging.h"

static const char *tag = "gpiod";

static int sysfs_unexport(unsigned int gpio_pin)
{
  int fd;
  int ret;
  char buf[256];

  fd = open("/sys/class/gpio/unexport", O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }

  snprintf(buf, 256, "%d", gpio_pin);

  ret = (int)write(fd, buf, strlen(buf));

  close(fd);

  return ret;
}

static int set_direction(gpio_gpiod_t *gpio, gpio_direction_t direction)
{
  if (gpio == NULL) {
    return -1;
  }

  if (direction == IN) {
    FATAL_ON(gpiod_line_request_input(gpio->line, tag) < 0);
  } else if (direction == OUT) {
    FATAL_ON(gpiod_line_request_output(gpio->line, tag, 0) < 0);
  } else if (direction == HIGH) {
    FATAL_ON(gpiod_line_request_output(gpio->line, tag, 1) < 0);
  }

  return 0;
}

static int set_edge(gpio_gpiod_t *gpio, gpio_edge_t edge)
{
  if (gpio == NULL) {
    return -1;
  }

  if (edge == BOTH) {
    FATAL_ON(gpiod_line_request_both_edges_events(gpio->line, tag) < 0);
  } else if (edge == FALLING) {
    FATAL_ON(gpiod_line_request_falling_edge_events(gpio->line, tag) < 0);
  } else if (edge == RISING) {
    FATAL_ON(gpiod_line_request_rising_edge_events(gpio->line, tag) < 0);
  }

  return 0;
}

int gpio_init(gpio_gpiod_t *gpio, const char *gpio_chip, unsigned int gpio_pin, gpio_direction_t direction, gpio_edge_t edge)
{
  struct gpiod_chip *chip;

  if (gpio == NULL) {
    return -1;
  }

  // In case we need to clean up after the sysfs interface
  sysfs_unexport(gpio_pin);

  gpio->chip_name = gpio_chip;
  gpio->pin = gpio_pin;
  gpio->irq_fd = -1;

  chip = gpiod_chip_open_by_name(gpio->chip_name);
  FATAL_ON(chip == NULL);

  gpio->line = gpiod_chip_get_line(chip, gpio->pin);
  FATAL_ON(gpio->line == NULL);

  if (direction == IN) {
    if (edge == NO_EDGE) {
      set_direction(gpio, direction);
    } else {
      set_edge(gpio, edge);
      gpio->irq_fd = gpiod_line_event_get_fd(gpio->line);
      FATAL_ON(gpio->irq_fd == -1);
    }
  } else {
    set_direction(gpio, direction);
  }

  return 0;
}

int gpio_deinit(gpio_gpiod_t *gpio)
{
  if (gpio == NULL) {
    return -1;
  }

  gpio->chip_name = NULL;

  if (gpio->line) {
    gpiod_line_release(gpio->line);
    gpio->line = NULL;
  }

  return 0;
}

int gpio_get_fd(gpio_gpiod_t *gpio)
{
  if (gpio == NULL) {
    return -1;
  }

  return gpio->irq_fd;
}

int gpio_clear_irq(gpio_gpiod_t *gpio)
{
  struct gpiod_line_event event;

  if (gpio == NULL) {
    return -1;
  }

  return gpiod_line_event_read(gpio->line, &event);
}

int gpio_write(gpio_gpiod_t *gpio, int value)
{
  int ret;

  if (gpio == NULL) {
    return -1;
  }

  ret = gpiod_line_set_value(gpio->line, value);
  FATAL_ON(ret < 0);

  return ret;
}

int gpio_read(gpio_gpiod_t *gpio)
{
  int ret;

  if (gpio == NULL) {
    return -1;
  }

  ret = gpiod_line_get_value(gpio->line);
  FATAL_ON(ret < 0);

  return ret;
}
