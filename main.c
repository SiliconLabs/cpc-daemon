/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Main
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
#include <pthread.h>

#include <stdbool.h>
#include <stddef.h>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/time.h>
#include <execinfo.h>
#include <errno.h>

#include "version.h"
#include "misc/logging.h"
#include "misc/config.h"
#include "modes/normal.h"
#include "modes/binding.h"
#include "modes/firmware_update.h"
#include "driver/driver_kill.h"
#include "security/security.h"
#include "server_core/server_core.h"
#include "server_core/epoll/epoll.h"

pthread_t main_thread = 0;
pthread_t driver_thread = 0;
pthread_t server_core_thread = 0;
pthread_t security_thread = 0;

static int main_crash_eventfd;
static int main_gracefull_exit_signalfd;
static int main_wait_crash_or_gracefull_exit_epoll;

static int exit_status = EXIT_SUCCESS;

/* Global copy of argv to be able to restart the daemon with the same arguments. */
char **argv_g = 0;

#define BT_BUF_SIZE 100

void main_wait_crash_or_gracefull_exit(void);

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

int main(int argc, char *argv[])
{
  argv_g = argv;

  main_thread = pthread_self();
  pthread_setname_np(main_thread, "cpcd");

  /* Setup signaling segfault */
  {
    struct sigaction sa = { 0 };

    sa.sa_handler = segv_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
  }

  /* Setup crash and gracefull exit signaling */
  {
    sigset_t mask;
    int ret;

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGQUIT);

    /* Block signals so that they aren't handled
       according to their default dispositions. */
    ret = sigprocmask(SIG_BLOCK, &mask, NULL);
    FATAL_ON(ret == -1);

    /* Create crash fd and signal fd */
    {
      main_crash_eventfd = eventfd(0, //Start with 0 value
                                   EFD_CLOEXEC);
      FATAL_ON(main_crash_eventfd == -1);

      main_gracefull_exit_signalfd = signalfd(-1, &mask, SFD_CLOEXEC);
      FATAL_ON(main_gracefull_exit_signalfd == -1);
    }

    /* Setup epoll for those fds */
    {
      struct epoll_event event = { .events = EPOLLIN };

      main_wait_crash_or_gracefull_exit_epoll = epoll_create1(EPOLL_CLOEXEC);
      FATAL_SYSCALL_ON(main_wait_crash_or_gracefull_exit_epoll < 0);

      ret = epoll_ctl(main_wait_crash_or_gracefull_exit_epoll,
                      EPOLL_CTL_ADD,
                      main_crash_eventfd,
                      &event);
      FATAL_SYSCALL_ON(ret < 0);

      ret = epoll_ctl(main_wait_crash_or_gracefull_exit_epoll,
                      EPOLL_CTL_ADD,
                      main_gracefull_exit_signalfd,
                      &event);
      FATAL_SYSCALL_ON(ret < 0);
    }
  }

  epoll_init();

  logging_init();

  PRINT_INFO("CPCd v%s", PROJECT_VER);
  PRINT_INFO("Git commit: %s / branch: %s", GIT_SHA1, GIT_REFSPEC);

  PRINT_INFO("Reading configuration file");

  config_init(argc, argv);

#if !defined(ENABLE_ENCRYPTION)
  PRINT_INFO("\033[31;1mENCRYPTION IS DISABLED \033[0m");
#else
  if (config_use_encryption == false) {
    PRINT_INFO("\033[31;1mENCRYPTION IS DISABLED \033[0m");
  }
#endif

  switch (config_operation_mode) {
    case MODE_NORMAL:
      PRINT_INFO("Starting daemon in normal mode");
      run_normal_mode();
      break;

    case MODE_BINDING_PLAIN_TEXT:
#if defined(ENABLE_ENCRYPTION)
      PRINT_INFO("Starting daemon in plain text binding mode");
      run_binding_mode();
#else
      FATAL("Tried to initiate binding mode with encryption disabled");
#endif
      break;

    case MODE_BINDING_ECDH:
#if defined(ENABLE_ENCRYPTION)
      PRINT_INFO("Starting daemon in ECDH binding mode");
      run_binding_mode();
#else
      FATAL("Tried to initiate binding mode with encryption disabled");
#endif
      break;

    case MODE_BINDING_UNBIND:
#if defined(ENABLE_ENCRYPTION)
      PRINT_INFO("Starting daemon in unbind mode");
      run_binding_mode();
#else
      FATAL("Tried to unbind with encryption disabled");
#endif
      break;

    case MODE_FIRMWARE_UPDATE:
      PRINT_INFO("Starting daemon in firmware update mode");
      run_firmware_update();
      break;

    default:
      BUG();
      break;
  }

  return 0;
}

/* Meant to be called by the main thread only */
__attribute__((noreturn)) static void exit_daemon(void)
{
  driver_kill_signal();
  pthread_join(driver_thread, NULL);

  server_core_kill_signal();
  pthread_join(server_core_thread, NULL);

  if (config_use_encryption && security_thread != 0) {
    int ret = pthread_tryjoin_np(security_thread, NULL);
    if (ret == EBUSY) {
#if defined(ENABLE_ENCRYPTION)
      security_kill_signal();
      pthread_join(security_thread, NULL);
#endif
    }
  }

  PRINT_INFO("Daemon exiting with status %s", (exit_status == 0) ? "EXIT_SUCCESS" : "EXIT_FAILURE");

  /* Block until all logging data is flushed */
  logging_kill();

  exit(exit_status);
}

void main_wait_crash_or_gracefull_exit(void)
{
  int event_count;
  struct epoll_event events;

  do {
    event_count = epoll_wait(main_wait_crash_or_gracefull_exit_epoll,
                             &events,
                             1, //only one event
                             -1); //no timeout
  } while (errno == EINTR && event_count < 0); // Ignore SIGSTOP

  FATAL_SYSCALL_ON(event_count <= 0);

  exit_daemon();
}

__attribute__((noreturn)) void signal_crash(void)
{
  const uint64_t event_value = 1; //doesn't matter what it is

  exit_status = EXIT_FAILURE;

  sleep(1); // Wait for logs to be flushed to the output

  if (pthread_self() == main_thread) {
    exit_daemon();
  } else {
    write(main_crash_eventfd, &event_value, sizeof(event_value));
  }

  pthread_exit(0);
}
