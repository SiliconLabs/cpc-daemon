/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Server core
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

#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>

#include "server_core.h"
#include "server.h"
#include "core.h"
#include "epoll.h"
#include "log.h"
#include "system.h"
#include "config.h"

#define MAX_EPOLL_EVENTS 1

#if !defined(UNIT_TESTING)
static bool set_reset_mode_ack = false;
#endif

static bool reset_ack = false;
static bool reset_reason_received = false;
static bool capabilites_received = false;

static enum {
  SET_REBOOT_MODE,
  WAIT_REBOOT_MODE_ACK,
  WAIT_RESET_ACK,
  WAIT_RESET_REASON,
  WAIT_FOR_RX_CAPABILITY,
  RESET_SEQUENCE_DONE
} reset_sequence_state = SET_REBOOT_MODE;

#if defined(UNIT_TESTING)
static uint32_t rx_capability = 1024;
#else
static uint32_t rx_capability = 0;
#endif

static void on_unsolicited_status(sl_cpc_system_status_t status);

static void* server_core_thread_func(void* param);

#if !defined(UNIT_TESTING)
static void process_reset_sequence(void);
static void property_set_reset_mode_callback(sl_cpc_system_command_handle_t *handle,
                                             sl_cpc_property_id_t property_id,
                                             void* property_value,
                                             size_t property_length,
                                             sl_status_t status);
#endif

void reset_callback(sl_cpc_system_command_handle_t *handle,
                    sl_status_t status,
                    sl_cpc_system_status_t reset_status);

static void cleanup_socket_folder(const char *folder)
{
  struct dirent *next_file;
  char filepath[255] = {};
  DIR *dir = opendir(folder);
  FATAL_SYSCALL_ON(dir == NULL);

  while ((next_file = readdir(dir)) != NULL) {
    strcpy(filepath, folder);
    strcat(filepath, next_file->d_name);
    if (strstr(filepath, ".cpcd.sock") != NULL) {
      TRACE_SERVER("Removing %s", filepath);
      FATAL_SYSCALL_ON(remove(filepath) < 0);
    }
  }
  closedir(dir);
}

uint32_t server_core_get_secondary_rx_capability(void)
{
  FATAL_ON(rx_capability == 0); // Need to go through reset sequence first
  return rx_capability;
}

pthread_t server_core_init(int fd_socket_driver_core)
{
  char socket_folder[255];
  struct stat sb;
  pthread_t server_core_thread;
  int ret;

  epoll_init();

  core_init(fd_socket_driver_core);

  sl_cpc_system_init();

#if !defined(UNIT_TESTING)
  sl_cpc_system_register_unsolicited_prop_last_status_callback(on_unsolicited_status);
#endif

  strcpy(socket_folder, config_socket_folder);
  strcat(socket_folder, "/cpcd/");

  /* Check if the socket folder exists */
  if (stat(socket_folder, &sb) == 0 && S_ISDIR(sb.st_mode)) {
    TRACE_SERVER("Cleaning up socket folder %s", socket_folder);
    cleanup_socket_folder(socket_folder);
  } else {
    TRACE_SERVER("Creating socket folder %s", socket_folder);
    mkdir(socket_folder, 0700);
    ret = access(socket_folder, W_OK);
    FATAL_SYSCALL_ON(ret < 0);
  }

  /* The server is not initialized immediately because we want to perform a successful reset sequence
   * of the secondary before. That is, unless we explicitly disable the reset sequence in the config file */
  if (config_reset_sequence == false) {
    /* FIXME : If we don't perform a reset sequence, the rx_capability won't be fetched. Lets put a very conservative
     * value in place to be able to work . */
    rx_capability = 256;
    server_init();
  }

#if defined(UNIT_TESTING)
  server_init();
#endif

  /* create driver thread */
  ret = pthread_create(&server_core_thread, NULL, server_core_thread_func, NULL);
  FATAL_ON(ret != 0);

  ret = pthread_setname_np(server_core_thread, "server_core");
  FATAL_ON(ret != 0);

  return server_core_thread;
}

static void* server_core_thread_func(void* param)
{
  (void) param;
  struct epoll_event events[MAX_EPOLL_EVENTS] = {};
  size_t event_count;

  while (1) {
#if !defined(UNIT_TESTING)
    if (config_reset_sequence == true) {
      process_reset_sequence();
    }
#endif

    core_process_transmit_queue();

    event_count = epoll_wait_for_event(events, MAX_EPOLL_EVENTS);

    /* Process each ready file descriptor*/
    {
      size_t event_i;
      for (event_i = 0; event_i != (size_t)event_count; event_i++) {
        epoll_private_data_t* private_data = (epoll_private_data_t*) events[event_i].data.ptr;
        private_data->callback(private_data);
      }
    }

    server_process_pending_connections();
  }

  return NULL;
}

#if !defined(UNIT_TESTING)
static void property_set_reset_mode_callback(sl_cpc_system_command_handle_t *handle,
                                             sl_cpc_property_id_t property_id,
                                             void* property_value,
                                             size_t property_length,
                                             sl_status_t status)
{
  (void) handle;
  (void) property_id;

  switch (status) {
    case SL_STATUS_IN_PROGRESS:
    case SL_STATUS_OK:

      if (property_length != sizeof(sl_cpc_system_status_t)) {
        TRACE_RESET("Set reset mode reply length doesn't match");
        FATAL();
      }

      sl_cpc_system_status_t* status = (sl_cpc_system_status_t*) property_value;

      if (*status != SL_STATUS_OK) {
        TRACE_RESET("Set reset mode could not be applied");
        FATAL();
      }

      set_reset_mode_ack = true;
      break;

    case SL_STATUS_TIMEOUT:
      TRACE_RESET("Set reset mode timed out!");

      break;

    case SL_STATUS_FAIL:
      TRACE_RESET("Set reset mode failed!");
      break;
    default:
      FATAL();
      break;
  }
}
#endif

void reset_callback(sl_cpc_system_command_handle_t *handle,
                    sl_status_t status,
                    sl_cpc_system_status_t reset_status)
{
  (void) handle;

  switch (status) {
    case SL_STATUS_IN_PROGRESS:
    case SL_STATUS_OK:

      if (reset_status == SL_STATUS_OK) {
        reset_ack = true;
      }
      break;

    case SL_STATUS_TIMEOUT:
      TRACE_SERVER("reset timed out!");
      break;

    case SL_STATUS_FAIL:
      TRACE_SERVER("reset failed!");
      break;
    default:
      FATAL();
      break;
  }
}

static void on_unsolicited_status(sl_cpc_system_status_t status)
{
  if (status <= STATUS_RESET_WATCHDOG && status >= STATUS_RESET_POWER_ON) {
    TRACE_RESET("Received reset reason : %u", status);

    if (reset_sequence_state == WAIT_RESET_REASON) {
      reset_reason_received = true;
    } else {
      TRACE_RESET("Secondary has reset, reset the daemon.");

      /* Stop driver immediately */
      {
        extern pthread_t driver_thread;

        pthread_cancel(driver_thread);
      }
      /* Notify lib connected */
      server_notify_connected_libs_of_secondary_reset();

      /* All file descriptors except stdout, stdin and stderr are supposed to be closed automatically with O_CLOEXEC */

      /* Restart the daemon with the same arguments as this process */
      {
        extern char **argv_g;

        /* Include argv[0] because its the name of the executable itself */
        execv("/proc/self/exe", argv_g);
      }
    }
  }
}

#if !defined(UNIT_TESTING)
static void property_get_rx_capability(sl_cpc_system_command_handle_t *handle,
                                       sl_cpc_property_id_t property_id,
                                       void* property_value,
                                       size_t property_length,
                                       sl_status_t status)
{
  (void)handle;

  FATAL_ON(property_id != PROP_RX_CAPABILITY);
  FATAL_ON(status != SL_STATUS_OK && status != SL_STATUS_IN_PROGRESS);
  FATAL_ON(property_value == NULL || property_length != sizeof(uint16_t));

  TRACE_RESET("Received RX capability of %u bytes", *((uint16_t *)property_value));
  capabilites_received = true;
  rx_capability = *((uint16_t *)property_value);
}

static void process_reset_sequence(void)
{
  switch (reset_sequence_state) {
    case RESET_SEQUENCE_DONE:
      return;

    case SET_REBOOT_MODE:
      /* Send a request to the secondary to set the reboot mode to 'application' */
    {
      const sl_cpc_system_reboot_mode_t reboot_mode = REBOOT_APPLICATION;

      sl_cpc_system_cmd_property_set(property_set_reset_mode_callback,
                                     5,      /* 5 retries */
                                     100000, /* 100ms between retries*/
                                     PROP_BOOTLOADER_REBOOT_MODE,
                                     &reboot_mode,
                                     sizeof(reboot_mode));

      reset_sequence_state = WAIT_REBOOT_MODE_ACK;

      TRACE_RESET("Reboot mode sent");
    }
    break;

    case WAIT_REBOOT_MODE_ACK:

      if (set_reset_mode_ack == true) {
        /* Now, request a reset  */
        sl_cpc_system_cmd_reset(reset_callback,
                                5,      /* 5 retries */
                                100000 /* 100ms between retries*/);

        reset_sequence_state = WAIT_RESET_ACK;

        TRACE_RESET("Reboot mode reply received, reset request sent");
      }
      break;

    case WAIT_RESET_ACK:

      if (reset_ack == true) {
        reset_sequence_state = WAIT_RESET_REASON;
        TRACE_RESET("Reset request acknowledged");
      }
      break;

    case WAIT_RESET_REASON:
      if (reset_reason_received == true) {
        TRACE_RESET("Reset reason received");
        sl_cpc_system_cmd_property_get(property_get_rx_capability,
                                       PROP_RX_CAPABILITY,
                                       5,       /* 5 retries */
                                       100000); /* 100ms between retries*/
        reset_sequence_state = WAIT_FOR_RX_CAPABILITY;
      }
      break;

    case WAIT_FOR_RX_CAPABILITY:
      if (capabilites_received == true) {
        TRACE_RESET("Obtained capabilites");
        reset_sequence_state = RESET_SEQUENCE_DONE;
        server_init();
      }
      break;

    default:
      FATAL("Impossible state");
      break;
  }
}
#endif
