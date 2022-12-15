/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Server core
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

#include <stdio.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <sys/un.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "misc/config.h"
#include "misc/logging.h"
#include "misc/sleep.h"
#include "misc/utils.h"
#include "modes/uart_validation.h"
#include "server_core.h"
#include "server_core/epoll/epoll.h"
#include "server_core/server/server.h"
#include "server_core/core/core.h"
#include "server_core/system_endpoint/system.h"
#include "security/security.h"
#include "version.h"
#include "driver/driver_kill.h"

#define MAX_EPOLL_EVENTS 1

char *server_core_secondary_app_version = NULL;
uint8_t server_core_secondary_protocol_version;
sl_cpc_bootloader_t server_core_secondary_bootloader_type = SL_CPC_BOOTLOADER_UNKNOWN;

static bool set_reset_mode_ack = false;

static bool reset_ack = false;
static bool secondary_cpc_version_received = false;
static bool secondary_app_version_received_or_not_available = false;
static bool bootloader_info_received_or_not_available = false;
static bool secondary_bus_speed_received = false;
static bool failed_to_receive_secondary_bus_speed = false;
static bool reset_reason_received = false;
static bool capabilities_received = false;
static bool rx_capability_received = false;
static bool protocol_version_received = false;

static server_core_mode_t server_core_mode = SERVER_CORE_MODE_NORMAL;

static sl_cpc_system_reboot_mode_t pending_mode;

static int kill_eventfd = -1;
static int security_ready_eventfd = -1;

static enum {
  SET_NORMAL_REBOOT_MODE,
  WAIT_NORMAL_REBOOT_MODE_ACK,
  WAIT_NORMAL_RESET_ACK,
  WAIT_RESET_REASON,
  WAIT_FOR_CAPABILITIES,
  WAIT_FOR_RX_CAPABILITY,
  WAIT_FOR_BOOTLOADER_INFO,
  WAIT_FOR_SECONDARY_CPC_VERSION,
  WAIT_FOR_SECONDARY_APP_VERSION,
  WAIT_FOR_PROTOCOL_VERSION,
  WAIT_FOR_SECONDARY_BUS_SPEED,
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

static uint32_t capabilities = 0;

static void on_unsolicited_status(sl_cpc_system_status_t status);

static void* server_core_thread_func(void* param);

#if !defined(UNIT_TESTING)
static void process_reset_sequence(bool firmware_reset_mode);
#endif

static void server_core_cleanup(epoll_private_data_t *private_data);

#if !defined(UNIT_TESTING)
static void security_property_get_state_callback(sl_cpc_system_command_handle_t *handle,
                                                 sl_cpc_property_id_t property_id,
                                                 void* property_value,
                                                 size_t property_length,
                                                 sl_status_t status);
#endif

static void security_fetch_remote_security_state(epoll_private_data_t *private_data);

static void property_set_reset_mode_callback(sl_cpc_system_command_handle_t *handle,
                                             sl_cpc_property_id_t property_id,
                                             void* property_value,
                                             size_t property_length,
                                             sl_status_t status);

static void process_reboot_enter_bootloader(void);

void reset_callback(sl_cpc_system_command_handle_t *handle,
                    sl_status_t status,
                    sl_cpc_system_status_t reset_status);

static void cleanup_socket_folder(const char *folder)
{
  struct dirent *next_file;
  char filepath[sizeof_member(struct sockaddr_un, sun_path)] = {};
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

void server_core_notify_security_ready(void)
{
  const uint64_t event_value = 1;
  ssize_t ret;

  if (security_ready_eventfd == -1) {
    return;
  }

  ret = write(security_ready_eventfd, &event_value, sizeof(event_value));
  FATAL_ON(ret != sizeof(event_value));
}

pthread_t server_core_init(int fd_socket_driver_core, int fd_socket_driver_core_notify, server_core_mode_t mode)
{
  char* socket_folder = NULL;
  struct stat sb = { 0 };
  pthread_t server_core_thread = { 0 };
  int ret = 0;

  core_init(fd_socket_driver_core, fd_socket_driver_core_notify);

  sl_cpc_system_init();

#if !defined(UNIT_TESTING)
  sl_cpc_system_register_unsolicited_prop_last_status_callback(on_unsolicited_status);
#endif

  /* Create the string {socket_folder}/cpcd/{instance_name} */
  {
    const size_t socket_folder_string_size = strlen(config.socket_folder) + strlen("/cpcd/") + strlen(config.instance_name) + sizeof(char);
    socket_folder = (char *)zalloc(socket_folder_string_size);
    FATAL_ON(socket_folder == NULL);

    ret = snprintf(socket_folder, socket_folder_string_size, "%s/cpcd/%s", config.socket_folder, config.instance_name);
    FATAL_ON(ret < 0 || (size_t) ret >= socket_folder_string_size);
  }

  /* Check if the socket folder exists */
  if (stat(socket_folder, &sb) == 0 && S_ISDIR(sb.st_mode)) {
    TRACE_SERVER("Cleaning up socket folder %s", socket_folder);
    cleanup_socket_folder(socket_folder);
  } else {
    TRACE_SERVER("Creating socket folder %s", socket_folder);
    recursive_mkdir(socket_folder, strlen(socket_folder), S_IRWXU | S_IRWXG | S_ISVTX);
    ret = access(socket_folder, W_OK);
    FATAL_SYSCALL_ON(ret < 0);
  }

  free(socket_folder);

  /* The server is not initialized immediately because we want to perform a successful reset sequence
   * of the secondary before. That is, unless we explicitly disable the reset sequence in the config file */
  if (config.reset_sequence == false) {
    /* FIXME : If we don't perform a reset sequence, the rx_capability won't be fetched. Lets put a very conservative
     * value in place to be able to work . */
    rx_capability = 256;
    server_init();
#if defined(ENABLE_ENCRYPTION)
    if (config.operation_mode != MODE_UART_VALIDATION) {
      security_init();
    }
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

  /* Setup event to be called when security has been initialized */
  {
    security_ready_eventfd = eventfd(0, EFD_CLOEXEC);
    FATAL_ON(security_ready_eventfd == -1);

    static epoll_private_data_t security_ready_data;

    security_ready_data.callback = security_fetch_remote_security_state;
    /* These fields are initialized but values are not relevant */
    security_ready_data.file_descriptor = security_ready_eventfd;
    security_ready_data.endpoint_number = 0;

    epoll_register(&security_ready_data);
  }

  /* create server_core thread */
  server_core_mode = mode;
  ret = pthread_create(&server_core_thread, NULL, server_core_thread_func, NULL);
  FATAL_ON(ret != 0);

  ret = pthread_setname_np(server_core_thread, "server_core");
  FATAL_ON(ret != 0);

  return server_core_thread;
}

static void* server_core_thread_func(void* param)
{
  (void)param;
  struct epoll_event events[MAX_EPOLL_EVENTS] = {};
  size_t event_count;

  while (1) {
#if !defined(UNIT_TESTING)
    if ((config.reset_sequence == true) && (server_core_mode == SERVER_CORE_MODE_NORMAL)) {
      process_reset_sequence(false);
    }

    if (server_core_mode == SERVER_CORE_MODE_FIRMWARE_RESET) {
      process_reset_sequence(true);
    }

    if (server_core_mode == SERVER_CORE_MODE_FIRMWARE_BOOTLOADER) {
      process_reboot_enter_bootloader();
    }
#endif

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

      switch (*mode) {
        case REBOOT_APPLICATION:
          if (pending_mode == REBOOT_BOOTLOADER) {
            FATAL("The secondary does not support rebooting into bootloader mode: application reboot received as a confirmation instead of bootloader.");
          }
          break;
        case REBOOT_BOOTLOADER:
          if (pending_mode != REBOOT_BOOTLOADER) {
            BUG("Requested reboot mode was not bootloader, but received it as a reply");
          }
          break;
        default:
          BUG("Reboot mode reply is unknown");
          break;
      }

      set_reset_mode_ack = true;
      break;

    case SL_STATUS_TIMEOUT:
    case SL_STATUS_ABORT:
      PRINT_INFO("Failed to connect, secondary seems unresponsive");
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
      WARN("Failed to reset Secondary");
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
  if (uart_validation_reset_requested(status)) {
    return;
  }

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
      int ret;

      PRINT_INFO("Secondary has reset, reset the daemon.");

      /* Stop driver immediately */
      ret = driver_kill_signal_and_join();
      FATAL_ON(ret != 0);

      /* Notify lib connected */
      server_notify_connected_libs_of_secondary_reset();

      /* Close every single endpoint data connections */
      for (uint8_t i = 1; i < 255; ++i) {
        server_close_endpoint(i, false);
      }

      /* Restart the daemon with the same arguments as this process */
      /* All file descriptors except stdout, stdin and stderr are supposed to be closed automatically with O_CLOEXEC */
      {
        extern char **argv_g;
        config_restart_cpcd(argv_g);
      }
    }
  }
}

char* server_core_get_secondary_app_version(void)
{
#if defined(UNIT_TESTING)
  return "UNDEFINED";
#else
  BUG_ON(server_core_secondary_app_version == NULL);
  return server_core_secondary_app_version;
#endif
}

#if !defined(UNIT_TESTING)
static void property_get_capabilities_callback(sl_cpc_system_command_handle_t *handle,
                                               sl_cpc_property_id_t property_id,
                                               void* property_value,
                                               size_t property_length,
                                               sl_status_t status)
{
  (void)handle;

  FATAL_ON(property_id != PROP_CAPABILITIES);
  FATAL_ON(status != SL_STATUS_OK && status != SL_STATUS_IN_PROGRESS);
  FATAL_ON(property_value == NULL || property_length != sizeof(uint32_t));

  capabilities = *((uint32_t *)property_value);

  if (capabilities & CPC_CAPABILITIES_SECURITY_ENDPOINT_MASK) {
    TRACE_RESET("Received capability : Security endpoint");
  }

  if (capabilities & CPC_CAPABILITIES_PACKED_ENDPOINT_MASK) {
    TRACE_RESET("Received capability : Packed endpoint");
  }

  if (capabilities & CPC_CAPABILITIES_GPIO_ENDPOINT_MASK) {
    TRACE_RESET("Received capability : GPIO endpoint");
  }

  if (capabilities & CPC_CAPABILITIES_UART_FLOW_CONTROL_MASK) {
    TRACE_RESET("Received capability : UART flow control");
  }

  capabilities_received = true;
}

static void property_get_rx_capability_callback(sl_cpc_system_command_handle_t *handle,
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
  rx_capability = *((uint16_t *)property_value);
  rx_capability_received = true;
}

static void property_get_secondary_bootloader_info(sl_cpc_system_command_handle_t *handle,
                                                   sl_cpc_property_id_t property_id,
                                                   void* property_value,
                                                   size_t property_length,
                                                   sl_status_t status)
{
  (void) handle;

  if ((status == SL_STATUS_OK || status == SL_STATUS_IN_PROGRESS) && property_id == PROP_BOOTLOADER_INFO) {
    FATAL_ON(property_value == NULL);
    FATAL_ON(property_length != 3 * sizeof(uint32_t));

    // property_value:
    //  [0]: bootloader type
    //  [1]: version (unused for now)
    //  [2]: capability mask (unused for now)
    server_core_secondary_bootloader_type = ((uint32_t*)property_value)[0];
    BUG_ON(server_core_secondary_bootloader_type >= SL_CPC_BOOTLOADER_UNKNOWN);

    PRINT_INFO("Secondary bootloader: %s",
               sl_cpc_system_bootloader_type_to_str((sl_cpc_bootloader_t)server_core_secondary_bootloader_type));
  } else {
    WARN("Cannot get secondary bootloader information");
  }

  bootloader_info_received_or_not_available = true;
}

static void property_get_secondary_cpc_version_callback(sl_cpc_system_command_handle_t *handle,
                                                        sl_cpc_property_id_t property_id,
                                                        void* property_value,
                                                        size_t property_length,
                                                        sl_status_t status)
{
  (void) handle;

  uint32_t version[3];
  memcpy(version, property_value, 3 * sizeof(uint32_t));

  if ( (property_id != PROP_SECONDARY_CPC_VERSION)
       || (status != SL_STATUS_OK && status != SL_STATUS_IN_PROGRESS)
       || (property_value == NULL || property_length != 3 * sizeof(uint32_t))) {
    FATAL("Cannot get Secondary CPC version (obsolete RCP firmware?)");
  }

  PRINT_INFO("Secondary CPC v%d.%d.%d", version[0], version[1], version[2]);
  secondary_cpc_version_received = true;
}

static void property_get_secondary_app_version_callback(sl_cpc_system_command_handle_t *handle,
                                                        sl_cpc_property_id_t property_id,
                                                        void* property_value,
                                                        size_t property_length,
                                                        sl_status_t status)
{
  (void) handle;

  if ((status == SL_STATUS_OK || status == SL_STATUS_IN_PROGRESS) && property_id == PROP_SECONDARY_APP_VERSION) {
    FATAL_ON(property_value == NULL);
    FATAL_ON(property_length == 0);

    const char *version = (const char *)property_value;

    BUG_ON(server_core_secondary_app_version);

    server_core_secondary_app_version = zalloc(property_length);
    FATAL_SYSCALL_ON(server_core_secondary_app_version == NULL);

    strncpy(server_core_secondary_app_version, version, property_length - 1);
    server_core_secondary_app_version[property_length - 1] = '\0';
    PRINT_INFO("Secondary APP v%s", server_core_secondary_app_version);
  } else {
    WARN("Cannot get Secondary APP version (obsolete RCP firmware?)");
  }

  secondary_app_version_received_or_not_available = true;
}

static void property_get_secondary_bus_speed_callback(sl_cpc_system_command_handle_t *handle,
                                                      sl_cpc_property_id_t property_id,
                                                      void* property_value,
                                                      size_t property_length,
                                                      sl_status_t status)
{
  (void) handle;
  uint32_t bus_speed = 0;

  if ((status == SL_STATUS_OK || status == SL_STATUS_IN_PROGRESS) && property_id == PROP_BUS_SPEED_VALUE) {
    FATAL_ON(property_value == NULL);
    FATAL_ON(property_length != sizeof(uint32_t));

    memcpy(&bus_speed, property_value, sizeof(uint32_t));

    PRINT_INFO("Secondary bus speed is %d", bus_speed);

    if (config.bus == UART && bus_speed != config.uart_baudrate) {
      FATAL("Baudrate mismatch (%d) on the daemon versus (%d) on the secondary",
            config.uart_baudrate, bus_speed);
    }

    secondary_bus_speed_received = true;
  } else {
    WARN("Could not obtain the secondary's bus speed");
    failed_to_receive_secondary_bus_speed = true;
  }
}

static void property_get_protocol_version_callback(sl_cpc_system_command_handle_t *handle,
                                                   sl_cpc_property_id_t property_id,
                                                   void* property_value,
                                                   size_t property_length,
                                                   sl_status_t status)
{
  (void) handle;

  uint8_t* version = (uint8_t*)property_value;

  if ((property_id != PROP_PROTOCOL_VERSION)
      || (status != SL_STATUS_OK && status != SL_STATUS_IN_PROGRESS)
      || (property_value == NULL || property_length != sizeof(uint8_t))) {
    FATAL("Cannot get Secondary Protocol version (obsolete RCP firmware?)");
  }

  server_core_secondary_protocol_version = *version;
  PRINT_INFO("Secondary Protocol v%d", server_core_secondary_protocol_version);

  protocol_version_received = true;
}

static void exit_server_core(void)
{
  int ret = driver_kill_signal_and_join();
  FATAL_ON(ret != 0);

  server_core_cleanup(NULL);
}

static void capabilities_checks(void)
{
  if ((config.bus == UART) && (config.uart_hardflow != (bool)(capabilities & CPC_CAPABILITIES_UART_FLOW_CONTROL_MASK))) {
    FATAL("UART flow control configuration mismatch between CPCd (%s) and Secondary (%s)",
          config.uart_hardflow ? "enabled" : "disabled",
          (bool)(capabilities & CPC_CAPABILITIES_UART_FLOW_CONTROL_MASK) ? "enabled" : "disabled");
  }

  if (config.use_encryption != (bool)(capabilities & CPC_CAPABILITIES_SECURITY_ENDPOINT_MASK)) {
    FATAL("Security configuration mismatch between CPCd (%s) and Secondary (%s)",
          config.use_encryption ? "enabled" : "disabled",
          (bool)(capabilities & CPC_CAPABILITIES_SECURITY_ENDPOINT_MASK) ? "enabled" : "disabled");
  }
}

static void protocol_version_check(void)
{
  if (server_core_secondary_protocol_version != PROTOCOL_VERSION) {
    FATAL("Secondary Protocol v%d doesn't match CPCd Protocol v%d",
          server_core_secondary_protocol_version, PROTOCOL_VERSION);
  }
}

static void application_version_check(void)
{
  if (config.application_version_validation && server_core_secondary_app_version) {
    if (strcmp(server_core_secondary_app_version,
               config.application_version_validation) != 0) {
      FATAL("Secondary APP v%s doesn't match the provided APP v%s",
            server_core_secondary_app_version, config.application_version_validation);
    }
  }
}

static void process_reset_sequence(bool firmware_reset_mode)
{
  switch (reset_sequence_state) {
    case RESET_SEQUENCE_DONE:
      return;

    case SET_NORMAL_REBOOT_MODE:
      PRINT_INFO("Connecting to Secondary...");

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
      if (reset_reason_received) {
        TRACE_RESET("Reset reason received");
        reset_sequence_state = WAIT_FOR_RX_CAPABILITY;
        sl_cpc_system_cmd_property_get(property_get_rx_capability_callback,
                                       PROP_RX_CAPABILITY,
                                       5,       /* 5 retries */
                                       100000,  /* 100ms between retries*/
                                       true);
      }
      break;

    case WAIT_FOR_RX_CAPABILITY:
      if (rx_capability_received) {
        TRACE_RESET("Obtained RX capability");
        PRINT_INFO("Connected to Secondary");
        reset_sequence_state = WAIT_FOR_PROTOCOL_VERSION;
        sl_cpc_system_cmd_property_get(property_get_protocol_version_callback,
                                       PROP_PROTOCOL_VERSION,
                                       5,      /* 5 retries */
                                       100000, /* 100ms between retries*/
                                       true);
      }
      break;

    case WAIT_FOR_PROTOCOL_VERSION:
      if (protocol_version_received) {
        TRACE_RESET("Obtained Protocol version");
        if (!firmware_reset_mode) {
          protocol_version_check();
        }
        reset_sequence_state = WAIT_FOR_CAPABILITIES;
        sl_cpc_system_cmd_property_get(property_get_capabilities_callback,
                                       PROP_CAPABILITIES,
                                       5,       /* 5 retries */
                                       100000,  /* 100ms between retries*/
                                       true);
      }
      break;

    case WAIT_FOR_CAPABILITIES:
      if (capabilities_received) {
        TRACE_RESET("Obtained Capabilites");
        if (!firmware_reset_mode) {
          capabilities_checks();

          reset_sequence_state = WAIT_FOR_SECONDARY_CPC_VERSION;
          sl_cpc_system_cmd_property_get(property_get_secondary_cpc_version_callback,
                                         PROP_SECONDARY_CPC_VERSION,
                                         5,       /* 5 retries */
                                         100000,  /* 100ms between retries*/
                                         true);
        } else {
          // Fetch bootloader information only if in firmware reset mode
          reset_sequence_state = WAIT_FOR_BOOTLOADER_INFO;
          sl_cpc_system_cmd_property_get(property_get_secondary_bootloader_info,
                                         PROP_BOOTLOADER_INFO,
                                         5,       /* 5 retries */
                                         100000,  /* 100ms between retries*/
                                         true);
        }
      }
      break;

    case WAIT_FOR_BOOTLOADER_INFO:
      if (bootloader_info_received_or_not_available) {
        TRACE_RESET("Obtained secondary bootloader information");

        reset_sequence_state = WAIT_FOR_SECONDARY_CPC_VERSION;
        sl_cpc_system_cmd_property_get(property_get_secondary_cpc_version_callback,
                                       PROP_SECONDARY_CPC_VERSION,
                                       5,       /* 5 retries */
                                       100000,  /* 100ms between retries*/
                                       true);
      }

      break;

    case WAIT_FOR_SECONDARY_CPC_VERSION:
      if (secondary_cpc_version_received) {
        TRACE_RESET("Obtained Secondary CPC version");

        reset_sequence_state = WAIT_FOR_SECONDARY_BUS_SPEED;
        sl_cpc_system_cmd_property_get(property_get_secondary_bus_speed_callback,
                                       PROP_BUS_SPEED_VALUE,
                                       5,       /* 5 retries */
                                       100000,  /* 100ms between retries*/
                                       true);
      }
      break;

    case WAIT_FOR_SECONDARY_BUS_SPEED:
      if (secondary_bus_speed_received || failed_to_receive_secondary_bus_speed) {
        reset_sequence_state = WAIT_FOR_SECONDARY_APP_VERSION;

        sl_cpc_system_cmd_property_get(property_get_secondary_app_version_callback,
                                       PROP_SECONDARY_APP_VERSION,
                                       5,       /* 5 retries */
                                       100000,  /* 100ms between retries*/
                                       true);
      }
      break;

    case WAIT_FOR_SECONDARY_APP_VERSION:
      if (secondary_app_version_received_or_not_available) {
        if (server_core_secondary_app_version) {
          TRACE_RESET("Obtained Secondary APP version");
        }

        if (config.print_secondary_versions_and_exit) {
          sleep_s(2);
          exit(EXIT_SUCCESS);
        }

        if (!firmware_reset_mode) {
          application_version_check();
        }

        reset_sequence_state = RESET_SEQUENCE_DONE;

        if (firmware_reset_mode) {
          exit_server_core();
        } else {
          server_init();
#if defined(ENABLE_ENCRYPTION)
          security_init();
#endif
          PRINT_INFO("Daemon startup was successful. Waiting for client connections");
        }
      }
      break;

    default:
      BUG("Impossible state");
      break;
  }
}

static void process_reboot_enter_bootloader(void)
{
  switch (reboot_into_bootloader_state) {
    case SET_BOOTLOADER_REBOOT_MODE:
      /* Send a request to the secondary to set the reboot mode to 'application' */
    {
      const sl_cpc_system_reboot_mode_t reboot_mode = REBOOT_BOOTLOADER;

      pending_mode = reboot_mode;

      sl_cpc_system_cmd_property_set(property_set_reset_mode_callback,
                                     1,         /* retry once */
                                     2000000,   /* 2s between retries*/
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
        TRACE_RESET("Reset request acknowledged");
        exit_server_core();
      }
      break;

    default:
      BUG("Impossible state");
      break;
  }
}
#endif

static void server_core_cleanup(epoll_private_data_t *private_data)
{
  (void) private_data;

  PRINT_INFO("Server core cleanup");

  sl_cpc_system_cleanup();

  pthread_exit(0);
}

#if !defined(UNIT_TESTING)
static void security_property_get_state_callback(sl_cpc_system_command_handle_t *handle,
                                                 sl_cpc_property_id_t property_id,
                                                 void* property_value,
                                                 size_t property_length,
                                                 sl_status_t status)
{
  (void)handle;
  (void)property_value;

  // The security state of the secondary is not currently used.
  // By receiving a response from the property get command we validate
  // that the link is encrypted because it was sent as an I-Frame

  // Secondary prior to v4.1.1 will return property_value STATUS_UNIMPLEMENTED
  // combined with property_id PROP_LAST_STATUS
  FATAL_ON(property_id != PROP_SECURITY_STATE && property_id != PROP_LAST_STATUS);

  if (status != SL_STATUS_OK && status != SL_STATUS_IN_PROGRESS) {
    FATAL("Failed to get security state on the remote. Possible binding key mismatch!");
  }

  FATAL_ON(property_length != sizeof(uint32_t));
}
#endif

static void security_fetch_remote_security_state(epoll_private_data_t *private_data)
{
  uint64_t event_value;
  ssize_t size;

  (void)private_data;

  size = read(security_ready_eventfd, &event_value, sizeof(event_value));
  FATAL_ON(size != sizeof(event_value));

#if !defined(UNIT_TESTING)
  sl_cpc_system_cmd_property_get(security_property_get_state_callback,
                                 PROP_SECURITY_STATE,
                                 1,
                                 1000000, // 1 second timeout
                                 false);  // Must be an i-frame to validate the encrypted link
#endif
}

bool server_core_reset_sequence_in_progress(void)
{
  return reset_sequence_state != RESET_SEQUENCE_DONE;
}
