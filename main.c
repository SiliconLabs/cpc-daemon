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
#include <unistd.h>
#include <sys/time.h>
#include <execinfo.h>

#include "version.h"
#include "misc/logging.h"
#include "misc/config.h"
#include "modes/normal.h"
#include "modes/binding.h"
#include "modes/firmware_update.h"

pthread_t driver_thread = 0;
pthread_t server_core_thread = 0;
pthread_t main_thread = 0;
pthread_t security_thread = 0;

/* Global copy of argv to be able to restart the daemon with the same arguments. */
char **argv_g;

static void main_sig_handler(int sig)
{
  (void) sig;
  cancel_all_threads(EXIT_SUCCESS);
}

#define BT_BUF_SIZE 100

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

  /* Setup signaling for this thread */
  {
    struct sigaction sa = { 0 };

    sa.sa_handler = main_sig_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    signal(SIGSEGV, segv_handler);   // install our handler
  }

  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

  main_thread = pthread_self();

  pthread_setname_np(main_thread, "main_thread");

  logging_init();

  PRINT_INFO("CPCd v%s", PROJECT_VER);

  PRINT_INFO("Reading configuration file");

  config_init(argc, argv);

  switch (config_operation_mode) {
    case MODE_NORMAL:
      PRINT_INFO("Starting daemon in normal mode");
      run_normal_mode();
      break;

    case MODE_BINDING_PLAIN_TEXT:
      PRINT_INFO("Starting daemon in binding mode");
      run_binding_mode();
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

/* Meant to be called by either the main, driver or server_core thread to
 * kill the process but allow the logging threads to flush the remaining
 * logging data. */
__attribute__((noreturn)) void cancel_all_threads(int status)
{
  static pthread_mutex_t crash_mutex = PTHREAD_MUTEX_INITIALIZER;

  /* Prevent two threads to crash at the same time */
  pthread_mutex_lock(&crash_mutex);
  {
    pthread_t self = pthread_self();

    /* Since the caller thread is either main, thread or server_core and
     * that we want to kill the two others, make sure we don't kill ourself
     * since we have a bit of work to do still. */
    {
      if (self != main_thread) {
        pthread_cancel(main_thread);
        //usleep(1000); /* BUG... */
        pthread_join(main_thread, NULL);
      }
      if (self != driver_thread) {
        pthread_cancel(driver_thread);
        //usleep(1000); /* BUG... */
        pthread_join(driver_thread, NULL);
      }
      if (self != server_core_thread) {
        pthread_cancel(server_core_thread);
        //usleep(1000); /* BUG... */
        pthread_join(server_core_thread, NULL);
      }
      if (self != security_thread) {
        pthread_cancel(security_thread);
        //usleep(1000); /* BUG... */
        pthread_join(security_thread, NULL);
      }
    }

    PRINT_INFO("Daemon exiting with status %s", (status == 0) ? "EXIT_SUCCESS" : "EXIT_FAILURE");

    /* Block until all logging data is flushed */
    logging_kill();

    exit(status);
  }
}
