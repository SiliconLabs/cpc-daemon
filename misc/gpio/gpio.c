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

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "gpio.h"
#include "log.h"

static int simple_write(const char *filename, const char *data);

static int gpio_getfd(unsigned int gpio_pin)
{
  int fd = 0;
  char buf[256];

  snprintf(buf, 256, "/sys/class/gpio/gpio%d/value", gpio_pin);
  fd = open(buf, O_RDWR | O_NONBLOCK | O_CLOEXEC);
  FATAL_SYSCALL_ON(fd < 0);

  return fd;
}

static int gpio_export(unsigned int gpio_pin)
{
  char buf[256];
  int ret;

  snprintf(buf, 256, "%d", gpio_pin);
  ret = simple_write("/sys/class/gpio/export", buf);

  //FIXME:
  // According to this post on stackexchange, this appears to be some sort of race condition bug.
  // Adding a strategic delay immediately after the export operation solves the problem.
  //https://raspberrypi.stackexchange.com/questions/23162/gpio-value-file-appears-with-wrong-permissions-momentarily
  usleep(100000);

  return ret;
}

static int gpio_unexport(unsigned int gpio_pin)
{
  char buf[256];

  snprintf(buf, 256, "%d", gpio_pin);
  return(simple_write("/sys/class/gpio/unexport", buf));
}

int gpio_init(gpio_t *gpio, unsigned int pin)
{
  if (gpio == NULL) {
    return -1;
  }

  gpio_unexport(pin);
  FATAL_ON(gpio_export(pin) < 0);

  gpio->value_fd = gpio_getfd(pin);

  gpio->irq_fd = gpio_getfd(pin);

  gpio->pin = pin;

  return gpio->value_fd;
}

int gpio_deinit(gpio_t *gpio)
{
  if (gpio == NULL) {
    return -1;
  }
  gpio_unexport(gpio->pin);
  close(gpio->value_fd);
  close(gpio->irq_fd);
  gpio->value_fd = -1;
  gpio->irq_fd = -1;
  gpio->pin = 0;
  return 0;
}

int gpio_direction(gpio_t gpio, gpio_direction_t direction)
{
  char buf[256];
  int ret = 0;

  snprintf(buf, 256, "/sys/class/gpio/gpio%d/direction", gpio.pin);

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

int gpio_setedge(gpio_t gpio, gpio_edge_t edge)
{
  char buf[256];
  int ret = 0;

  snprintf(buf, 256, "/sys/class/gpio/gpio%d/edge", gpio.pin);

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

int gpio_write(gpio_t gpio, int value)
{
  int ret = 0;

  if (value == 1) {
    ret = (int)write(gpio.value_fd, "1", strlen("1"));
  } else if (value == 0) {
    ret = (int)write(gpio.value_fd, "0", strlen("0"));
  }

  FATAL_SYSCALL_ON(ret != 1);

  return ret;
}

int gpio_read(gpio_t gpio)
{
  ssize_t ret = 0;
  char state;

  ret = lseek(gpio.value_fd, 0, SEEK_SET);
  FATAL_SYSCALL_ON(ret < 0);
  ret = read(gpio.value_fd, &state, 1);
  FATAL_SYSCALL_ON(ret < 0);

  if (state == '0') {
    return 0;
  } else {
    return 1;
  }
}

static int simple_write(const char *filename, const char *data)
{
  int fd;
  int ret;

  fd = open(filename, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }

  ret = (int)write(fd, data, strlen(data));
  if (ret < 0) {
    close(fd);
    return ret;
  }

  close(fd);

  return ret;
}
