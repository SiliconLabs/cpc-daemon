/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Exit Daemon
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

#include "config.h"

#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <errno.h>

#include "cpcd/exit.h"
#include "cpcd/server_core.h"
#include "cpcd/logging.h"
#include "driver/driver_kill.h"
#include "cpcd/sleep.h"

#if defined(HAVE_BACKTRACE)
#include "backtrace.h"
#define BT_BUF_SIZE 100
static void segv_handler(int sig);
#endif

static pthread_t main_thread;
static int exit_status = EXIT_SUCCESS;
static int crash_eventfd;
static int graceful_exit_eventfd;
static int graceful_exit_signalfd;
static int wait_crash_or_graceful_exit_epoll;

void exit_init(pthread_t main_thread_id)
{
  sigset_t mask;
  int ret;

  #if defined(HAVE_BACKTRACE)
  // Setup signaling segfault
  struct sigaction sa = { 0 };
  sa.sa_handler = segv_handler;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGSEGV, &sa, NULL);
  #endif

  main_thread = main_thread_id;

  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGQUIT);

  // Block signals so that they aren't handled
  // according to their default dispositions.
  ret = sigprocmask(SIG_BLOCK, &mask, NULL);
  FATAL_SYSCALL_ON(ret == -1);

  // Create crash fd and signal fd
  {
    crash_eventfd = eventfd(0,   // Start with 0 value
                            EFD_CLOEXEC);
    FATAL_SYSCALL_ON(crash_eventfd == -1);

    graceful_exit_eventfd = eventfd(0,   // Start with 0 value
                                    EFD_CLOEXEC);
    FATAL_SYSCALL_ON(graceful_exit_eventfd == -1);

    graceful_exit_signalfd = signalfd(-1, &mask, SFD_CLOEXEC);
    FATAL_SYSCALL_ON(graceful_exit_signalfd == -1);
  }

  // Setup epoll for those fds
  {
    struct epoll_event event = { .events = EPOLLIN };

    wait_crash_or_graceful_exit_epoll = epoll_create1(EPOLL_CLOEXEC);
    FATAL_SYSCALL_ON(wait_crash_or_graceful_exit_epoll < 0);

    ret = epoll_ctl(wait_crash_or_graceful_exit_epoll,
                    EPOLL_CTL_ADD,
                    crash_eventfd,
                    &event);
    FATAL_SYSCALL_ON(ret < 0);

    ret = epoll_ctl(wait_crash_or_graceful_exit_epoll,
                    EPOLL_CTL_ADD,
                    graceful_exit_eventfd,
                    &event);
    FATAL_SYSCALL_ON(ret < 0);

    ret = epoll_ctl(wait_crash_or_graceful_exit_epoll,
                    EPOLL_CTL_ADD,
                    graceful_exit_signalfd,
                    &event);
    FATAL_SYSCALL_ON(ret < 0);
  }
}

void wait_crash_or_graceful_exit(void)
{
  int event_count;
  struct epoll_event events;

  do {
    event_count = epoll_wait(wait_crash_or_graceful_exit_epoll,
                             &events,
                             1, // Only one event
                             -1); // No timeout
  } while (errno == EINTR && event_count < 0); // Ignore SIGSTOP

  FATAL_SYSCALL_ON(event_count <= 0);

  exit_daemon();
}

__attribute__((noreturn)) void signal_crash(void)
{
  const uint64_t event_value = 1; //doesn't matter what it is

  exit_status = EXIT_FAILURE;

  if (pthread_equal(pthread_self(), main_thread)) {
    exit_daemon();
  } else {
    ssize_t wc;
    wc = write(crash_eventfd, &event_value, sizeof(event_value));
    (void)wc;
  }

  pthread_exit(NULL);
}

__attribute__((noreturn)) void exit_daemon(void)
{
  driver_kill();

  server_core_kill();

  PRINT_INFO("Daemon exiting with status %s", (exit_status == 0) ? "EXIT_SUCCESS" : "EXIT_FAILURE");

  // Block until all logging data is flushed
  logging_kill();

  exit(exit_status);
}

__attribute__((noreturn)) void software_graceful_exit(void)
{
  const uint64_t event_value = 1; // Doesn't matter what it is

  exit_status = EXIT_SUCCESS;

  sleep_s(1); // Wait for logs to be flushed to the output

  if (pthread_self() == main_thread) {
    exit_daemon();
  } else {
    ssize_t wc;
    wc = write(graceful_exit_eventfd, &event_value, sizeof(event_value));
    (void)wc;
  }

  pthread_exit(NULL);
}

#if defined(HAVE_BACKTRACE)
static void segv_handler(int sig)
{
  (void) sig;
  int nptrs;
  void *buffer[BT_BUF_SIZE];
  char **strings;

  fprintf(stderr, "SEGFAULT :\n");

  nptrs = backtrace(buffer, BT_BUF_SIZE);
  fprintf(stderr, "backtrace() returned %d addresses\n", nptrs);

  // print out all the frames to stderr

  strings = backtrace_symbols(buffer, nptrs);
  if (strings == NULL) {
    perror("backtrace_symbols");
    exit(EXIT_FAILURE);
  }

  for (int j = 0; j < nptrs; j++) {
    fprintf(stderr, "%s\n", strings[j]);
  }

  exit(EXIT_FAILURE);
}
#endif
