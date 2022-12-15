/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - GPIO Sysfs Interface
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

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "gpio.h"
#include "logging.h"
#include "sleep.h"

static int get_fd(unsigned int gpio_pin);

static int simple_write(const char *filename, const char *data)
{
  int fd;
  int ret;

  fd = open(filename, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }

  ret = (int)write(fd, data, strlen(data));

  close(fd);

  return ret;
}

static int export (unsigned int gpio_pin)
{
  char buf[256];
  int ret;

  snprintf(buf, 256, "%d", gpio_pin);
  ret = simple_write("/sys/class/gpio/export", buf);
  FATAL_SYSCALL_ON(ret < 0);

  for (int i = 0; i < 5; i++) {
    // According to this post on stackexchange, this appears to be some sort of race condition bug.
    // Adding a strategic delay immediately after the export operation solves the problem. On some
    // occurrences, the 100ms delay was not enough, so handle the situation in a for loop to get
    // better chances of success.
    // https://raspberrypi.stackexchange.com/questions/23162/gpio-value-file-appears-with-wrong-permissions-momentarily
    sleep_ms(100);

    ret = get_fd(gpio_pin);
    if (ret != -1) {
      break;
    } else {
      FATAL_SYSCALL_ON(errno != EACCES);
    }
  }

  return ret;
}

static int unexport(unsigned int gpio_pin)
{
  char buf[256];

  snprintf(buf, 256, "%d", gpio_pin);
  return simple_write("/sys/class/gpio/unexport", buf);
}

static int get_fd(unsigned int gpio_pin)
{
  int fd = 0;
  char buf[256];

  snprintf(buf, 256, "/sys/class/gpio/gpio%d/value", gpio_pin);
  fd = open(buf, O_RDWR | O_NONBLOCK | O_CLOEXEC);

  return fd;
}

static int set_direction(gpio_sysfs_t *gpio, gpio_direction_t direction)
{
  char buf[256];
  int ret = 0;

  snprintf(buf, 256, "/sys/class/gpio/gpio%d/direction", gpio->pin);

  if (direction == IN) {
    ret = simple_write(buf, "in");
    FATAL_SYSCALL_ON(ret != 2);
  } else if (direction == OUT) {
    ret = simple_write(buf, "out");
    FATAL_SYSCALL_ON(ret != 3);
  } else if (direction == HIGH) {
    ret = simple_write(buf, "high");
    FATAL_SYSCALL_ON(ret != 4);
  }

  return ret;
}

static int set_edge(gpio_sysfs_t *gpio, gpio_edge_t edge)
{
  char buf[256];
  int ret = 0;

  snprintf(buf, 256, "/sys/class/gpio/gpio%d/edge", gpio->pin);

  if (edge == BOTH) {
    ret = simple_write(buf, "both");
    FATAL_SYSCALL_ON(ret != 4);
  } else if (edge == FALLING) {
    ret = simple_write(buf, "falling");
    FATAL_SYSCALL_ON(ret != 7);
  } else if (edge == RISING) {
    ret = simple_write(buf, "rising");
    FATAL_SYSCALL_ON(ret != 6);
  }

  return ret;
}

int gpio_init(gpio_sysfs_t *gpio, const char *gpio_chip, unsigned int gpio_pin, gpio_direction_t direction, gpio_edge_t edge)
{
  if (gpio == NULL) {
    return -1;
  }

  (void)gpio_chip;

  unexport(gpio_pin);

  gpio->value_fd = export (gpio_pin);
  FATAL_ON(gpio->value_fd < 0);

  gpio->irq_fd = get_fd(gpio_pin);
  gpio->pin = gpio_pin;

  FATAL_ON(set_direction(gpio, direction) < 0);

  FATAL_ON(set_edge(gpio, edge) < 0);

  return 0;
}

int gpio_deinit(gpio_sysfs_t *gpio)
{
  if (gpio == NULL) {
    return -1;
  }

  unexport(gpio->pin);
  close(gpio->value_fd);
  close(gpio->irq_fd);
  gpio->value_fd = -1;
  gpio->irq_fd = -1;
  gpio->pin = 0;
  return 0;
}

int gpio_get_fd(gpio_sysfs_t *gpio)
{
  if (gpio == NULL) {
    return -1;
  }

  return gpio->irq_fd;
}

int gpio_clear_irq(gpio_sysfs_t *gpio)
{
  char buf[8];

  if (gpio == NULL) {
    return -1;
  }

  lseek(gpio->irq_fd, 0, SEEK_SET);
  read(gpio->irq_fd, buf, sizeof(buf));

  return 0;
}

int gpio_write(gpio_sysfs_t *gpio, int value)
{
  int ret = 0;

  if (value == 1) {
    ret = (int)write(gpio->value_fd, "1", strlen("1"));
  } else if (value == 0) {
    ret = (int)write(gpio->value_fd, "0", strlen("0"));
  }

  FATAL_SYSCALL_ON(ret != 1);

  return ret;
}

int gpio_read(gpio_sysfs_t *gpio)
{
  ssize_t ret = 0;
  char state;

  ret = lseek(gpio->value_fd, 0, SEEK_SET);
  FATAL_SYSCALL_ON(ret < 0);
  ret = read(gpio->value_fd, &state, 1);
  FATAL_SYSCALL_ON(ret < 0);

  if (state == '0') {
    return 0;
  } else {
    return 1;
  }
}
