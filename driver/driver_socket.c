/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) - Socket driver
 *******************************************************************************
 * # License
 * <b>Copyright 2024 Silicon Laboratories Inc. www.silabs.com</b>
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

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <pthread.h>

#include "cpcd/config.h"
#include "cpcd/logging.h"

#include "driver/driver_kill.h"
#include "driver/driver_socket.h"

#define MAX_EPOLL_EVENTS 1

typedef void (*driver_epoll_callback_t)(void);

static int fd_core;
static int fd_core_notify;
static int fd_epoll;
static int fd_driver_socket = -1;
static int fd_data_socket = -1;
pthread_mutex_t fd_data_socket_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t drv_thread;
struct sockaddr_un addr;

static void driver_socket_cleanup(void);
static void driver_socket_process_from_core(void);
static void driver_socket_process_new_connection(void);
static void driver_socket_process_from_emulated_secondary(void);
static void* driver_thread_func(void* param);

static void set_nonblocking(int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    perror("fcntl");
    exit(EXIT_FAILURE);
  }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    perror("fcntl");
    exit(EXIT_FAILURE);
  }
}

pthread_t driver_socket_init(int *fd_to_core,
                             int *fd_notify_core)
{
  int fd_sockets_notify[2];
  int fd_sockets[2];
  int ret;

  // Create socketpair for communicating with the core.
  ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets);
  FATAL_SYSCALL_ON(ret < 0);

  fd_core  = fd_sockets[0];
  *fd_to_core = fd_sockets[1];

  ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets_notify);
  FATAL_SYSCALL_ON(ret < 0);

  fd_core_notify  = fd_sockets_notify[0];
  *fd_notify_core = fd_sockets_notify[1];

  fd_driver_socket = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (fd_driver_socket == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;

  {
    const size_t size = sizeof(addr.sun_path) - 1;
    int nchars;

    nchars = snprintf(addr.sun_path,
                      size,
                      "%s/cpcd/%s/driver.sock",
                      config.socket_folder,
                      config.instance_name);

    // Make sure the path fitted entirely in the struct's static buffer.
    FATAL_ON(nchars < 0 || (size_t) nchars >= size);
  }

  ret = unlink(addr.sun_path);
  // FATAL_SYSCALL_ON(ret < 0);
  if (ret < 0 && errno != ENOENT) {
    perror("unlink");
    close(fd_driver_socket);
    exit(EXIT_FAILURE);
  }

  // Bind the socket to a file.
  ret = bind(fd_driver_socket, (const struct sockaddr *) &addr, sizeof(addr));
  FATAL_SYSCALL_ON(ret < 0);

  // Set backlog to 10. TODO check if this is necessary.
  ret = listen(fd_driver_socket, 10);
  FATAL_SYSCALL_ON(ret < 0);

  // Setup epoll.
  struct epoll_event event = {};

  // Create the epoll set.
  fd_epoll = epoll_create1(EPOLL_CLOEXEC);
  FATAL_SYSCALL_ON(fd_epoll < 0);

  // Setup the socket to the core.
  // Level-triggered read() availability.
  event.events = EPOLLIN;
  event.data.ptr = driver_socket_process_from_core;
  ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_core, &event);
  FATAL_SYSCALL_ON(ret < 0);

  // Setup the socket used to emulate the secondary.
  // Level-triggered and edge-triggered read() availability.
  event.events = EPOLLIN | EPOLLET;
  event.data.ptr = driver_socket_process_new_connection;
  ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_driver_socket, &event);
  FATAL_SYSCALL_ON(ret < 0);

  driver_kill_init(driver_socket_cleanup);

  // Epoll processing thread.
  ret = pthread_create(&drv_thread, NULL, driver_thread_func, NULL);
  FATAL_ON(ret != 0);

  // Useful to debug multithreaded. Possible cause of unstable connection?
  ret = pthread_setname_np(drv_thread, "drv_thread");
  FATAL_ON(ret != 0);

  TRACE_DRIVER("Driver Socket Init Done");

  return drv_thread;
}

static void driver_socket_process_from_core(void)
{
  uint8_t buffer[4096];
  ssize_t write_retval;
  ssize_t read_retval;

  // Read data coming from the core.
  read_retval = read(fd_core, buffer, sizeof(buffer));
  FATAL_SYSCALL_ON(read_retval < 0);

  // If client is connected yet, do not write(). Print frame and return early.
  if (fd_data_socket == -1) {
    // return;
  } else {
    // Push it to the socket representing the secondary.
    pthread_mutex_lock(&fd_data_socket_mutex);
    write_retval = write(fd_data_socket, buffer, (size_t)read_retval);
    pthread_mutex_unlock(&fd_data_socket_mutex);
    FATAL_ON(read_retval != write_retval);
  }

  // Prepare and push notification to the core.
  struct timespec tx_complete_timestamp;
  clock_gettime(CLOCK_MONOTONIC, &tx_complete_timestamp);

  write_retval = write(fd_core_notify, &tx_complete_timestamp, sizeof(tx_complete_timestamp));
  FATAL_SYSCALL_ON(write_retval != sizeof(tx_complete_timestamp));
}

static void driver_socket_process_new_connection(void)
{
  struct sockaddr_un addr;
  socklen_t addrlen = sizeof(addr);
  struct epoll_event event = {};

  int ret;
  int fd_data_socket_temp = -1;

  // FATAL_ON(fd_data_socket != -1);

  fd_data_socket_temp = accept(fd_driver_socket, (struct sockaddr *)&addr, &addrlen);
  FATAL_SYSCALL_ON(fd_data_socket_temp < 0);

  // Set fd_data_socket to non-blocking.
  set_nonblocking(fd_data_socket_temp);

  // Setup the socket used to emulate the secondary.
  // Level-triggered and edge-triggered read() availability.
  event.events = EPOLLIN;
  event.data.ptr = driver_socket_process_from_emulated_secondary;
  ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_data_socket_temp, &event);
  // FATAL_SYSCALL_ON(ret < 0);
  if (ret == -1) {
    perror("epoll_ctl");
    close(fd_data_socket_temp);
  } else {
    pthread_mutex_lock(&fd_data_socket_mutex);
    if (fd_data_socket != -1) {
      close(fd_data_socket);
    }
    fd_data_socket = fd_data_socket_temp;
    pthread_mutex_unlock(&fd_data_socket_mutex);
  }
}

// Read data from secondary and send to CPC core.
static void driver_socket_process_from_emulated_secondary(void)
{
  uint8_t buffer[4096];
  ssize_t write_retval;
  ssize_t read_retval;

  // Do not simply kill the server.
  // FATAL_ON(fd_data_socket == -1);
  if (fd_data_socket == -1) {
    return;
  }

  errno = 0;

  read_retval = read(fd_data_socket, buffer, sizeof(buffer));

  // FATAL_SYSCALL_ON(read_retval < 0);
  if (read_retval < 0) {
    if (errno == EAGAIN) {
      return;
    }
    if (errno == EINTR || errno == EPIPE || errno == ECONNRESET) {
      return;
    } else {
      perror("read");
      epoll_ctl(fd_epoll, EPOLL_CTL_DEL, fd_data_socket, NULL);
      pthread_mutex_lock(&fd_data_socket_mutex);
      close(fd_data_socket);
      fd_data_socket = -1;
      pthread_mutex_unlock(&fd_data_socket_mutex);
      return;
    }
  } else if (read_retval == 0) {
    // Connection closed by the client.
    epoll_ctl(fd_epoll, EPOLL_CTL_DEL, fd_data_socket, NULL);
    pthread_mutex_lock(&fd_data_socket_mutex);
    close(fd_data_socket);
    fd_data_socket = -1;
    pthread_mutex_unlock(&fd_data_socket_mutex);
    return;
  } else {
    // Send data from secondary to CPC core.
    write_retval = write(fd_core, buffer, (size_t)read_retval);

    FATAL_SYSCALL_ON(write_retval != read_retval);
    return;
  }
  return;
}

static void driver_socket_cleanup(void)
{
  int ret;

  if (fd_data_socket != -1) {
    close(fd_data_socket);
  }

  close(fd_driver_socket);
  ret = unlink(addr.sun_path);
  // FATAL_SYSCALL_ON(ret < 0);
  if (ret < 0 && errno != ENOENT) {
    perror("unlink");
    close(fd_driver_socket);
    exit(EXIT_FAILURE);
  }

  close(fd_epoll);
}

// Thread to process the epoll events.
static void* driver_thread_func(void* param)
{
  (void) param;
  struct epoll_event events[MAX_EPOLL_EVENTS] = {};
  int event_count;

  while (1) {
    // Wait for action.
    {
      do {
        event_count = epoll_wait(fd_epoll, events, MAX_EPOLL_EVENTS, -1);
        if (event_count == -1 && errno == EINTR) {
          continue;
        }
        FATAL_SYSCALL_ON(event_count == -1);
        break;
      } while (1);

      // Timeouts should not occur.
      FATAL_ON(event_count == 0);
    }

    // Process each ready file descriptor.
    {
      size_t event_i;
      for (event_i = 0; event_i != (size_t)event_count; event_i++) {
        driver_epoll_callback_t callback = (driver_epoll_callback_t) events[event_i].data.ptr;
        callback();
      }
    }
  }

  return 0;
}
