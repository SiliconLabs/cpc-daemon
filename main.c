/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Main
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

#include <pthread.h>

#include <stdbool.h>
#include <stddef.h>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>

#include "cpcd/exit.h"
#include "cpcd/config.h"
#include "cpcd/logging.h"
#include "cpcd/modes.h"
#include "cpcd/security.h"
#include "cpcd/server_core.h"

#include "version.h"
#include "driver/driver_kill.h"
#include "server_core/epoll/epoll.h"

pthread_t main_thread; // Current thread

/* Global copy of argv to be able to restart the daemon with the same arguments. */
char **argv_g = 0;
int argc_g = 0;

int main(int argc, char *argv[])
{
  argc_g = argc;
  argv_g = argv;
  bool secondary_already_running_bootloader = false;

  main_thread = pthread_self();
  pthread_setname_np(main_thread, "cpcd");

  /* Setup crash and graceful exit signaling */
  exit_init(main_thread);

  epoll_init();

  logging_init();

  PRINT_INFO("[CPCd v%s] [Library API v%d] [RCP Protocol v%d]", PROJECT_VER, LIBRARY_API_VERSION, PROTOCOL_VERSION);
  PRINT_INFO("Git commit: %s / branch: %s", GIT_SHA1, GIT_REFSPEC);
  PRINT_INFO("Sources hash: %s", SOURCES_HASH);

  if (geteuid() == 0) {
    WARN("Running CPCd as 'root' is not recommended. Proceed at your own risk.");
  }

  config_init(argc, argv);

#if !defined(ENABLE_ENCRYPTION)
  PRINT_INFO("\033[31;1mENCRYPTION IS DISABLED \033[0m");
#else
  if (config.use_encryption == false) {
    PRINT_INFO("\033[31;1mENCRYPTION IS DISABLED \033[0m");
  }
#endif

  if (config.reset_sequence) {
    secondary_already_running_bootloader = is_bootloader_running();
  }

  if (secondary_already_running_bootloader) {
    PRINT_INFO("The bootloader has been detected to be currently running on the secondary. This can be caused by :");
    PRINT_INFO("- A secondary which only has the bootloader flashed and no CPC application.");
    PRINT_INFO("- A previously failed firmware upgrade.");
    PRINT_INFO("- A previous daemon invocation with -e parameter (to put the secondary in bootloader mode and exit).");
  }

  switch (config.operation_mode) {
    case MODE_NORMAL:
      PRINT_INFO("Starting daemon in normal mode");

      if (secondary_already_running_bootloader) {
        FATAL("Cannot run CPCd in normal mode because the bootloader is currently running on the secondary.");
      }

      run_normal_mode();
      break;

    case MODE_BINDING_PLAIN_TEXT:
#if defined(ENABLE_ENCRYPTION)
      PRINT_INFO("Starting daemon in plain text binding mode");

      if (secondary_already_running_bootloader) {
        FATAL("Cannot run CPCd in binding plain-text mode because the bootloader is currently running on the secondary.");
      }

      run_binding_mode();
#else
      FATAL("Tried to initiate binding mode with encryption disabled");
#endif
      break;

    case MODE_BINDING_ECDH:
#if defined(ENABLE_ENCRYPTION)
      PRINT_INFO("Starting daemon in ECDH binding mode");

      if (secondary_already_running_bootloader) {
        FATAL("Cannot run CPCd in binding ECDH mode because the bootloader is currently running on the secondary.");
      }

      run_binding_mode();
#else
      FATAL("Tried to initiate binding mode with encryption disabled");
#endif
      break;

    case MODE_BINDING_UNBIND:
#if defined(ENABLE_ENCRYPTION)
      PRINT_INFO("Starting daemon in unbind mode");

      if (secondary_already_running_bootloader) {
        FATAL("Cannot run CPCd in unbind mode because the bootloader is currently running on the secondary.");
      }

      run_binding_mode();
#else
      FATAL("Tried to unbind with encryption disabled");
#endif
      break;

    case MODE_FIRMWARE_UPDATE:
      PRINT_INFO("Starting daemon in firmware update mode");
      run_firmware_update();
      break;

    case MODE_UART_VALIDATION:
      PRINT_INFO("Starting daemon in UART validation mode");

      if (secondary_already_running_bootloader) {
        FATAL("Cannot run CPCd in UART validation mode because the bootloader is currently running on the secondary.");
      }

      run_uart_validation();
      break;

    default:
      BUG();
      break;
  }

  return 0;
}
