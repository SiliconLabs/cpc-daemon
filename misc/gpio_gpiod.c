/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - GPIO Gpiod Interface
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
#define _GNU_SOURCE

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

#include "gpio.h"
#include "logging.h"

static const char *tag = "gpiod";

static void *thread_func(void *arg)
{
  gpio_gpiod_t *irq_gpio = (gpio_gpiod_t *)arg;
  struct gpiod_line_event event = { 0 };
  const struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };

  TRACE_GPIOD("Thread start (%s-%d)", irq_gpio->chip_name, irq_gpio->pin);

  // Trigger initial irq to replicate sysfs behavior
  FATAL_SYSCALL_ON(write(irq_gpio->fd_socketpair[1], &event, sizeof(struct gpiod_line_event)) < 0);

  while (1) {
    int ret = gpiod_line_event_wait(irq_gpio->line, &timeout);
    FATAL_ON(ret < 0);
    if (ret == 1) {
      FATAL_ON(gpiod_line_event_read(irq_gpio->line, &event) < 0);
      FATAL_SYSCALL_ON(write(irq_gpio->fd_socketpair[1], &event, sizeof(struct gpiod_line_event)) < 0);
    }
  }
}

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

  if (edge != NO_EDGE) {
    char thread_name[16] = { 0 };
    int flags;

    // Create socket pair for epoll
    FATAL_SYSCALL_ON(socketpair(AF_UNIX, SOCK_DGRAM, 0, gpio->fd_socketpair) < 0);

    // Non blocking socket
    flags = fcntl(gpio->fd_socketpair[0], F_GETFL, 0);
    FATAL_SYSCALL_ON(flags < 0);
    FATAL_SYSCALL_ON(fcntl(gpio->fd_socketpair[0], F_SETFL, flags | O_NONBLOCK) < 0);

    // Create thread
    FATAL_ON(pthread_create(&gpio->thread, NULL, thread_func, gpio) != 0);

    // Assign thread name
    FATAL_ON(snprintf(thread_name, sizeof(thread_name), "%s-%d", gpio->chip_name, gpio->pin) < 0);
    FATAL_ON(pthread_setname_np(gpio->thread, thread_name) != 0);
  } else {
    gpio->thread = 0;
    gpio->fd_socketpair[0] = -1;
    gpio->fd_socketpair[1] = -1;
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

  chip = gpiod_chip_open_by_name(gpio->chip_name);
  FATAL_ON(chip == NULL);

  gpio->line = gpiod_chip_get_line(chip, gpio->pin);
  FATAL_ON(gpio->line == NULL);

  FATAL_ON(direction != NO_DIRECTION && edge != NO_EDGE);

  FATAL_ON(set_direction(gpio, direction) < 0);

  FATAL_ON(set_edge(gpio, edge) < 0);

  return 0;
}

int gpio_deinit(gpio_gpiod_t *gpio)
{
  if (gpio == NULL) {
    return -1;
  }

  if (gpio->thread) {
    pthread_cancel(gpio->thread);
    pthread_join(gpio->thread, NULL);
    TRACE_GPIOD("Thread cancel (%s-%d)", gpio->chip_name, gpio->pin);
    gpio->thread = 0;
  }

  gpio->chip_name = NULL;

  if (gpio->line) {
    gpiod_line_release(gpio->line);
    gpio->line = NULL;
  }

  if (gpio->fd_socketpair[0] > 0) {
    close(gpio->fd_socketpair[0]);
    gpio->fd_socketpair[0] = -1;
  }

  if (gpio->fd_socketpair[1] > 0) {
    close(gpio->fd_socketpair[1]);
    gpio->fd_socketpair[1] = -1;
  }

  return 0;
}

int gpio_get_fd(gpio_gpiod_t *gpio)
{
  if (gpio == NULL) {
    return -1;
  }

  return gpio->fd_socketpair[0];
}

int gpio_clear_irq(gpio_gpiod_t *gpio)
{
  struct gpiod_line_event event;

  if (gpio == NULL) {
    return -1;
  }

  read(gpio->fd_socketpair[0], &event, sizeof(struct gpiod_line_event));

  return 0;
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
