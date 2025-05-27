#include "config.h"

#include <linux/gpio.h>

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdlib.h>

#include "cpcd/gpio.h"
#include "cpcd/logging.h"

// POSIX defines the second argument of ioctl function as int. That's
// how musl defines it too. But Glibc, Linux kernel and BSD OSes define
// it as unsigned long. This mismatch causes a compilation warning [1].
// [1] https://www.openwall.com/lists/musl/2020/01/20/2
#if defined(__GLIBC__)
#define ioctl(d, req, ...) ioctl((d), (unsigned int)(req), __VA_ARGS__)
#endif

static const char* direction_to_str(gpio_direction_t direction)
{
  switch (direction) {
    case GPIO_DIRECTION_IN:
      return "IN";
    case GPIO_DIRECTION_OUT:
      return "OUT";
    default:
      BUG();
  }

  return "";
}

static const char* edge_to_str(gpio_edge_t edge)
{
  switch (edge) {
    case GPIO_EDGE_FALLING:
      return "FALLING";
    case GPIO_EDGE_RISING:
      return "RISING";
    case GPIO_EDGE_BOTH:
      return "BOTH";
    case GPIO_EDGE_NO_EDGE:
      return "NO_EDGE";
    default:
      BUG();
  }

  return "";
}

gpio_t gpio_init(const char *gpio_chip, unsigned int gpio_pin, gpio_direction_t direction, gpio_edge_t edge)
{
  int ret;
  int chip_fd;
  char gpio_chip_name_buffer[256];
  gpio_t gpio;

  TRACE_GPIO("Opening gpio #%u on chip %s. Direction : %s, edge : %s", gpio_pin, gpio_chip, direction_to_str(direction), edge_to_str(edge));

  // If an EDGE is configured, the direction must be IN
  BUG_ON(edge != GPIO_EDGE_NO_EDGE && direction == GPIO_DIRECTION_OUT);

  ret = snprintf(gpio_chip_name_buffer, sizeof(gpio_chip_name_buffer), "/dev/%s", gpio_chip);
  FATAL_ON(ret < 0 || (size_t) ret > sizeof(gpio_chip_name_buffer));

  chip_fd = open(gpio_chip_name_buffer, O_RDONLY | O_CLOEXEC);
  FATAL_SYSCALL_ON(chip_fd < 0);

  if (direction == GPIO_DIRECTION_IN) {
    struct gpioevent_request rq = { 0 };
    rq.lineoffset = gpio_pin;
    rq.handleflags = GPIOHANDLE_REQUEST_INPUT;

    switch (edge) {
      case GPIO_EDGE_FALLING:
        rq.eventflags = GPIOEVENT_EVENT_FALLING_EDGE;
        break;
      case GPIO_EDGE_RISING:
        rq.eventflags = GPIOEVENT_EVENT_RISING_EDGE;
        break;
      case GPIO_EDGE_BOTH:
        rq.eventflags = GPIOEVENT_REQUEST_BOTH_EDGES;
        break;
      case GPIO_EDGE_NO_EDGE:
        rq.eventflags = 0;
        break;
      default:
        BUG();
        break;
    }

    ret = ioctl(chip_fd, (int)GPIO_GET_LINEEVENT_IOCTL, &rq);
    if (ret < 0) {
      FATAL("%m : The kernel must be configured with CONFIG_GPIO_CDEV_V1=y");
    }

    gpio = (gpio_t) rq.fd;

    ret = fcntl(gpio, F_SETFL, O_NONBLOCK);
    FATAL_SYSCALL_ON(ret < 0);
  } else {
    struct gpiohandle_request rq;
    memset(&rq, 0, sizeof(rq));
    rq.lineoffsets[0] = gpio_pin;
    rq.flags = GPIOHANDLE_REQUEST_OUTPUT;
    rq.lines = 1;

    ret = ioctl(chip_fd, (int)GPIO_GET_LINEHANDLE_IOCTL, &rq);
    if (ret < 0) {
      FATAL("%m : The kernel must be configured with CONFIG_GPIO_CDEV_V1=y");
    }

    gpio = (gpio_t) rq.fd;
  }

  ret = fcntl(gpio, F_SETFD, FD_CLOEXEC);
  FATAL_SYSCALL_ON(ret < 0);

  // Don't need the chip file descriptor anymore
  ret = close(chip_fd);
  FATAL_SYSCALL_ON(ret < 0);

  return gpio;
}

void gpio_deinit(gpio_t gpio)
{
  int ret = close((int) gpio);
  FATAL_SYSCALL_ON(ret < 0);
}

void gpio_write(gpio_t gpio, gpio_value_t value)
{
  struct gpiohandle_data data;
  int ret;

  BUG_ON(value != 0 && value != 1);

  data.values[0] = value;

  ret = ioctl(gpio, (int)GPIOHANDLE_SET_LINE_VALUES_IOCTL, &data);
  FATAL_SYSCALL_ON(ret < 0);
}

gpio_value_t gpio_read(gpio_t gpio)
{
  struct gpiohandle_data data;
  int ret;

  ret = ioctl(gpio, (int)GPIOHANDLE_GET_LINE_VALUES_IOCTL, &data);
  FATAL_SYSCALL_ON(ret < 0);

  return (gpio_value_t) data.values[0];
}

int gpio_get_epoll_fd(gpio_t gpio)
{
  // The epoll file descriptor is the gpio_t itself
  return gpio;
}

void gpio_clear_irq(gpio_t gpio)
{
  struct gpioevent_data event;
  ssize_t ret;

  // Clear only one IRQ event, more may still be in the 16 event kernel FIFO
  // The file descriptor has O_NONBLOCK, so this call won't block if no interrupt
  // is pending
  ret = read(gpio, &event, sizeof(struct gpioevent_data));
  if (ret < 0) {
    // EAGAIN is valid since it means clearing an interrupt event when there was
    // was none in the event buffer
    FATAL_SYSCALL_ON(errno != EAGAIN);
  } else {
    // Clearing a single gpio event was asked, a single gpio event cleared must be returned
    FATAL_SYSCALL_ON((size_t)ret != sizeof(struct gpioevent_data));
  }
}
