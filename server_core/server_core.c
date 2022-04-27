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
#define _GNU_SOURCE
#include <pthread.h>

#include <stdio.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "server_core.h"
#include "server_core/epoll/epoll.h"
#include "server_core/server/server.h"
#include "server_core/core/core.h"
#include "server_core/system_endpoint/system.h"
#include "security/security.h"
#include "misc/logging.h"
#include "misc/config.h"
#include "version.h"
#include "driver/driver_kill.h"

#define MAX_EPOLL_EVENTS 1

static bool set_reset_mode_ack = false;

static bool reset_ack = false;
static bool secondary_version_received = false;
static bool reset_reason_received = false;
static bool capabilites_received = false;
static bool protocol_version_received_and_match = false;

static sl_cpc_system_reboot_mode_t pending_mode;

static int kill_eventfd = -1;

static enum {
  SET_NORMAL_REBOOT_MODE,
  WAIT_NORMAL_REBOOT_MODE_ACK,
  WAIT_NORMAL_RESET_ACK,
  WAIT_RESET_REASON,
  WAIT_FOR_RX_CAPABILITY,
  WAIT_FOR_SECONDARY_VERSION,
  WAIT_FOR_PROTOCOL_VERSION,
  RESET_SEQUENCE_DONE
} reset_sequence_state = SET_NORMAL_REBOOT_MODE;

static enum {
  SET_BOOTLOADER_REBOOT_MODE,
  WAIT_BOOTLOADER_REBOOT_MODE_ACK,
  WAIT_BOOTLOADER_RESET_ACK
} reboot_into_bootloader_state = SET_BOOTLOADER_REBOOT_MODE;

bool ignore_reset_reason = true;

#if defined(UNIT_TESTING)
static uint32_t rx_capability = 1024;
#else
static uint32_t rx_capability = 0;
#endif

static int recursive_mkdir(const char *dir, const mode_t mode);

static void on_unsolicited_status(sl_cpc_system_status_t status);

static void* server_core_thread_func(void* param);

#if !defined(UNIT_TESTING)
static void process_reset_sequence(void);
#endif

static void server_core_cleanup(epoll_private_data_t *private_data);

static void property_set_reset_mode_callback(sl_cpc_system_command_handle_t *handle,
                                             sl_cpc_property_id_t property_id,
                                             void* property_value,
                                             size_t property_length,
                                             sl_status_t status);

static void process_reboot_into_bootloader_mode(void);

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
    strcat(filepath, "/");
    strcat(filepath, next_file->d_name);
    if (strstr(filepath, ".cpcd.sock") != NULL) {
      TRACE_SERVER("Removing %s", filepath);
      FATAL_SYSCALL_ON(remove(filepath) < 0);
    }
  }
  closedir(dir);
}

/* recursive mkdir */
static int recursive_mkdir(const char *dir, const mode_t mode)
{
  const size_t dirlen = strlen(dir) + sizeof('\0');
  char *tmp = NULL;
  char *p = NULL;
  struct stat sb;

  tmp = malloc(dirlen);
  FATAL_ON(tmp == NULL);

  /* copy path */
  strcpy(tmp, dir);

  /* remove trailing slash */
  if (tmp[dirlen - 1] == '/') {
    tmp[dirlen - 1] = '\0';
  }

  /* check if path exists and is a directory */
  if (stat(tmp, &sb) == 0) {
    if (S_ISDIR(sb.st_mode)) {
      goto return_ok;
    }
  }

  /* recursive mkdir */
  for (p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = 0;
      /* test path */
      if (stat(tmp, &sb) != 0) {
        /* path does not exist - create directory */
        if (mkdir(tmp, mode) < 0) {
          goto return_err;
        }
      } else if (!S_ISDIR(sb.st_mode)) {
        /* not a directory */
        goto return_err;
      }
      *p = '/';
    }
  }

  /* test path */
  if (stat(tmp, &sb) != 0) {
    /* path does not exist - create directory */
    if (mkdir(tmp, mode) < 0) {
      goto return_err;
    }
  } else if (!S_ISDIR(sb.st_mode)) {
    /* not a directory */
    goto return_err;
  }

  /* Fall through to return_ok */

  return_ok:
  free(tmp);
  return 0;

  return_err:
  free(tmp);
  return -1;
}

uint32_t server_core_get_secondary_rx_capability(void)
{
  FATAL_ON(rx_capability == 0); // Need to go through reset sequence first
  return rx_capability;
}

void server_core_kill_signal(void)
{
  ssize_t ret;
  const uint64_t event_value = 1; //doesn't matter what it is

  if (kill_eventfd == -1) {
    return;
  }

  ret = write(kill_eventfd, &event_value, sizeof(event_value));
  FATAL_ON(ret != sizeof(event_value));
}

pthread_t server_core_init(int fd_socket_driver_core, bool firmware_update)
{
  char* socket_folder = NULL;
  struct stat sb = { 0 };
  pthread_t server_core_thread = { 0 };
  int ret = 0;

  core_init(fd_socket_driver_core);

  sl_cpc_system_init();

#if !defined(UNIT_TESTING)
  sl_cpc_system_register_unsolicited_prop_last_status_callback(on_unsolicited_status);
#endif

  /* Create the string {socket_folder}/cpcd/{instance_name} */
  {
    const size_t socket_folder_string_size = strlen(config_socket_folder) + strlen("/cpcd/") + strlen(config_instance_name) + sizeof('\0');
    socket_folder = malloc(socket_folder_string_size);
    FATAL_ON(socket_folder == NULL);

    sprintf(socket_folder, "%s/cpcd/%s", config_socket_folder, config_instance_name);
  }

  /* Check if the socket folder exists */
  if (stat(socket_folder, &sb) == 0 && S_ISDIR(sb.st_mode)) {
    TRACE_SERVER("Cleaning up socket folder %s", socket_folder);
    cleanup_socket_folder(socket_folder);
  } else {
    TRACE_SERVER("Creating socket folder %s", socket_folder);
    recursive_mkdir(socket_folder, S_IRWXU | S_IRWXG | S_ISVTX);
    ret = access(socket_folder, W_OK);
    FATAL_SYSCALL_ON(ret < 0);
  }

  free(socket_folder);

  /* The server is not initialized immediately because we want to perform a successful reset sequence
   * of the secondary before. That is, unless we explicitly disable the reset sequence in the config file */
  if (config_reset_sequence == false) {
    /* FIXME : If we don't perform a reset sequence, the rx_capability won't be fetched. Lets put a very conservative
     * value in place to be able to work . */
    rx_capability = 256;
    server_init();
#if defined(ENABLE_ENCRYPTION)
    security_init();
#endif
  }

#if defined(UNIT_TESTING)
  server_init();
#endif

  /* Setup the kill eventfd */
  {
    kill_eventfd = eventfd(0, //Start with 0 value
                           EFD_CLOEXEC);
    FATAL_ON(kill_eventfd == -1);

    static epoll_private_data_t private_data;

    private_data.callback = server_core_cleanup;
    private_data.file_descriptor = kill_eventfd; /* Irrelevant here */
    private_data.endpoint_number = 0; /* Irrelevant here */

    epoll_register(&private_data);
  }

  /* create server_core thread */
  ret = pthread_create(&server_core_thread, NULL, server_core_thread_func, (void*)firmware_update);
  FATAL_ON(ret != 0);

  ret = pthread_setname_np(server_core_thread, "server_core");
  FATAL_ON(ret != 0);

  return server_core_thread;
}

static void* server_core_thread_func(void* param)
{
  bool firmware_update = (bool) param;
  struct epoll_event events[MAX_EPOLL_EVENTS] = {};
  size_t event_count;

  while (1) {
#if !defined(UNIT_TESTING)
    if (config_reset_sequence == true) {
      process_reset_sequence();
    }
#endif

    if (firmware_update) {
      process_reboot_into_bootloader_mode();
    }

    core_process_transmit_queue();

    event_count = epoll_wait_for_event(events, MAX_EPOLL_EVENTS);

    /* Process each ready file descriptor*/
    size_t event_i;
    for (event_i = 0; event_i != (size_t)event_count; event_i++) {
      epoll_private_data_t* private_data = (epoll_private_data_t*) events[event_i].data.ptr;
      private_data->callback(private_data);
    }

    server_process_pending_connections();
  }

  return NULL;
}

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
        FATAL("Set reset mode reply length doesn't match");
      }

      BUG_ON(property_length != sizeof(sl_cpc_system_reboot_mode_t));

      sl_cpc_system_reboot_mode_t* mode = (sl_cpc_system_reboot_mode_t*) property_value;

      BUG_ON(*mode != pending_mode);

      set_reset_mode_ack = true;
      break;

    case SL_STATUS_TIMEOUT:
    case SL_STATUS_ABORT:
      PRINT_INFO("Failed to connect to secondary.");
      ignore_reset_reason = false; // Don't ignore a secondary that resets
      reset_sequence_state = SET_NORMAL_REBOOT_MODE;
      break;
    default:
      BUG("Unhandled property_set_reset_mode_callback status");
      break;
  }
}

void reset_callback(sl_cpc_system_command_handle_t *handle,
                    sl_status_t status,
                    sl_cpc_system_status_t reset_status)
{
  (void) handle;

  switch (status) {
    case SL_STATUS_IN_PROGRESS:
    case SL_STATUS_OK:

      TRACE_RESET("Reset request response received : %d", reset_status);

      if (reset_status == SL_STATUS_OK) {
        reset_ack = true;
      }
      break;

    case SL_STATUS_TIMEOUT:
    case SL_STATUS_ABORT:
      WARN("Failed to reset secondary");
      ignore_reset_reason = false; // Don't ignore a secondary that resets
      reset_sequence_state = SET_NORMAL_REBOOT_MODE;
      break;
    default:
      BUG("Unhandled reset_callback status");
      break;
  }
}

static void on_unsolicited_status(sl_cpc_system_status_t status)
{
  if (ignore_reset_reason) {
    ignore_reset_reason = false;
    TRACE_RESET("Ignored reset reason : %u", status);
    return;
  }

  if (status <= STATUS_RESET_WATCHDOG && status >= STATUS_RESET_POWER_ON) {
    TRACE_RESET("Received reset reason : %u", status);
    TRACE_RESET("Reset sequence: %u", reset_sequence_state);

    if (reset_sequence_state == WAIT_RESET_REASON) {
      reset_reason_received = true;
    } else {
      PRINT_INFO("Secondary has reset, reset the daemon.");

      /* Stop driver immediately */
      {
        extern pthread_t driver_thread;

        pthread_cancel(driver_thread);
      }

      /* Notify lib connected */
      server_notify_connected_libs_of_secondary_reset();

      /* Close every single endpoint data connections */
      for (uint8_t i = 1; i < 255; ++i) {
        server_close_endpoint(i, false);
      }

      /* Wait for logs to be flushed */
      sleep(1);

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

static void property_get_secondary_version_callback(sl_cpc_system_command_handle_t *handle,
                                                    sl_cpc_property_id_t property_id,
                                                    void* property_value,
                                                    size_t property_length,
                                                    sl_status_t status)
{
  uint32_t* version = (uint32_t*)property_value;
  (void) handle;

  FATAL_ON(property_id != PROP_SECONDARY_VERSION);
  FATAL_ON(status != SL_STATUS_OK && status != SL_STATUS_IN_PROGRESS);
  FATAL_ON(property_value == NULL || property_length != 3 * sizeof(uint32_t));

  PRINT_INFO("Secondary is v%d.%d.%d", version[0], version[1], version[2]);
  secondary_version_received = true;
}

static void property_get_protocol_version_callback(sl_cpc_system_command_handle_t *handle,
                                                   sl_cpc_property_id_t property_id,
                                                   void* property_value,
                                                   size_t property_length,
                                                   sl_status_t status)
{
  (void) handle;
  uint8_t* version = (uint8_t*)property_value;

  FATAL_ON(property_id != PROP_PROTOCOL_VERSION);
  FATAL_ON(status != SL_STATUS_OK && status != SL_STATUS_IN_PROGRESS);
  FATAL_ON(property_value == NULL || property_length != sizeof(uint8_t));

  if (*version != PROTOCOL_VERSION) {
    FATAL("The secondary's protocol version (%d) doesn't match daemon's version(%d)", *version, PROTOCOL_VERSION);
  }

  PRINT_INFO("Protocol version is v%d", *version);

  protocol_version_received_and_match = true;
}

static void process_reset_sequence(void)
{
  switch (reset_sequence_state) {
    case RESET_SEQUENCE_DONE:
      return;

    case SET_NORMAL_REBOOT_MODE:
      PRINT_INFO("Connecting to secondary...");

      /* Send a request to the secondary to set the reboot mode to 'application' */
      {
        const sl_cpc_system_reboot_mode_t reboot_mode = REBOOT_APPLICATION;

        pending_mode = reboot_mode;

        sl_cpc_system_cmd_property_set(property_set_reset_mode_callback,
                                       1,       /* retry once */
                                       2000000, /* 2s between retries*/
                                       PROP_BOOTLOADER_REBOOT_MODE,
                                       &reboot_mode,
                                       sizeof(reboot_mode),
                                       true);

        reset_sequence_state = WAIT_NORMAL_REBOOT_MODE_ACK;

        TRACE_RESET("Reboot mode sent");
      }
      break;

    case WAIT_NORMAL_REBOOT_MODE_ACK:

      if (set_reset_mode_ack == true) {
        /* Now, request a reset  */
        sl_cpc_system_cmd_reboot(reset_callback,
                                 5,     /* 5 retries */
                                 100000 /* 100ms between retries*/);

        reset_sequence_state = WAIT_NORMAL_RESET_ACK;

        /* Set it back to false because it will be used for the bootloader reboot sequence */
        set_reset_mode_ack = false;

        TRACE_RESET("Reboot mode reply received, reset request sent");
      }
      break;

    case WAIT_NORMAL_RESET_ACK:

      if (reset_ack == true) {
        reset_sequence_state = WAIT_RESET_REASON;

        /* Set it back to false because it will be used for the bootloader reboot sequence */
        reset_ack = false;

        TRACE_RESET("Reset request acknowledged");
      }
      break;

    case WAIT_RESET_REASON:
      TRACE_RESET("Waiting for reset reason");
      if (reset_reason_received == true) {
        TRACE_RESET("Reset reason received");

        sl_cpc_system_cmd_property_get(property_get_rx_capability,
                                       PROP_RX_CAPABILITY,
                                       5,       /* 5 retries */
                                       100000,  /* 100ms between retries*/
                                       true);
        reset_sequence_state = WAIT_FOR_RX_CAPABILITY;
      }
      break;

    case WAIT_FOR_RX_CAPABILITY:
      if (capabilites_received == true) {
        TRACE_RESET("Obtained capabilites");
        PRINT_INFO("Connected to secondary");
        reset_sequence_state = WAIT_FOR_PROTOCOL_VERSION;
        sl_cpc_system_cmd_property_get(property_get_protocol_version_callback,
                                       PROP_PROTOCOL_VERSION,
                                       5,       /* 5 retries */
                                       100000, /* 100ms between retries*/
                                       true);
      }
      break;

    case WAIT_FOR_PROTOCOL_VERSION:
      if (protocol_version_received_and_match == true) {
        TRACE_RESET("Matching protocol version with the secondary");
        reset_sequence_state = WAIT_FOR_SECONDARY_VERSION;
        sl_cpc_system_cmd_property_get(property_get_secondary_version_callback,
                                       PROP_SECONDARY_VERSION,
                                       5,       /* 5 retries */
                                       100000, /* 100ms between retries*/
                                       true);
      }
      break;

    case WAIT_FOR_SECONDARY_VERSION:
      if (secondary_version_received == true) {
        TRACE_RESET("Obtained secondary version");
        reset_sequence_state = RESET_SEQUENCE_DONE;
        server_init();
#if defined(ENABLE_ENCRYPTION)
        security_init();
#endif
        PRINT_INFO("Daemon startup was successful. Waiting for client connections");
      }
      break;

    default:
      BUG("Impossible state");
      break;
  }
}
#endif

static void process_reboot_into_bootloader_mode(void)
{
  switch (reboot_into_bootloader_state) {
    case SET_BOOTLOADER_REBOOT_MODE:
      /* This sequence can only begin when the reset sequence is completed*/
      if (reset_sequence_state != RESET_SEQUENCE_DONE) {
        return;
      }

      /* Send a request to the secondary to set the reboot mode to 'application' */
      {
        const sl_cpc_system_reboot_mode_t reboot_mode = REBOOT_BOOTLOADER;

        pending_mode = reboot_mode;

        sl_cpc_system_cmd_property_set(property_set_reset_mode_callback,
                                       1,       /* retry once */
                                       2000000, /* 2s between retries*/
                                       PROP_BOOTLOADER_REBOOT_MODE,
                                       &reboot_mode,
                                       sizeof(reboot_mode),
                                       true);

        reboot_into_bootloader_state = WAIT_BOOTLOADER_REBOOT_MODE_ACK;

        TRACE_RESET("Bootloader reboot mode sent");
      }
      break;

    case WAIT_BOOTLOADER_REBOOT_MODE_ACK:
      if (set_reset_mode_ack == true) {
        /* Now, request a reset  */
        sl_cpc_system_cmd_reboot(reset_callback,
                                 5,     /* 5 retries */
                                 100000 /* 100ms between retries*/);

        reboot_into_bootloader_state = WAIT_BOOTLOADER_RESET_ACK;

        TRACE_RESET("Reboot mode reply received, reset request sent");
      }
      break;

    case WAIT_BOOTLOADER_RESET_ACK:
      if (reset_ack == true) {
        void* join_value;
        int ret;

        TRACE_RESET("Reset request acknowledged");

        driver_kill_signal();

        extern pthread_t driver_thread;
        ret = pthread_join(driver_thread, &join_value);
        FATAL_ON(ret != 0);
        FATAL_ON(join_value != 0);

        server_core_cleanup(NULL);
      }
      break;

    default:
      BUG("Impossible state");
      break;
  }
}

static void server_core_cleanup(epoll_private_data_t *private_data)
{
  (void) private_data;

  TRACE_RESET("Server core cleanup");

  pthread_exit(0);
}

bool server_core_reset_sequence_in_progress(void)
{
  return reset_sequence_state != RESET_SEQUENCE_DONE;
}
