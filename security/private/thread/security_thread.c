/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Security Endpoint
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

#include <errno.h>
#include <stdbool.h>

#include "misc/config.h"
#include "misc/logging.h"
#include "misc/sleep.h"
#include "server_core/server/server_ready_sync.h"
#include "security/private/thread/security_thread.h"
#include "security/private/thread/command_synchronizer.h"
#include "security/private/keys/keys.h"
#include "security/private/protocol/protocol.h"
#include "security/security.h"
#include "sl_cpc.h"

/* Library handles */
static cpc_handle_t lib_handle;

cpc_endpoint_t security_ep;

bool security_initialized = false;

#define SECURITY_READ_TIMEOUT_SEC 10

static void security_open_security_endpoint(void);
static void security_reconnect(void);

void* security_thread_func(void* param)
{
  (void)param;
  int ret;

  FATAL_ON(config.operation_mode == MODE_BINDING_UNKNOWN);

  security_keys_init();

  /* The server can take time to be up; try to to load the key first
   * to crash early if its bad. */
  if (config.operation_mode != MODE_BINDING_ECDH && config.operation_mode != MODE_BINDING_UNBIND) {
    security_load_binding_key_from_file();
  }

  /* Block until the server is up and running */
  server_ready_wait();

  ret = cpc_init(&lib_handle, config.instance_name, false, NULL);
  FATAL_ON(ret < 0);

  security_open_security_endpoint();

  security_set_state(SECURITY_STATE_INITIALIZING);
  security_initialized = true;

  TRACE_SECURITY("Initialized the security endpoint");

  while (1) {
    sl_cpc_security_command_t command = security_wait_for_command();

    /* An event request is pending, act on it */
    switch (command) {
      case SECURITY_COMMAND_NONE:
        WARN("SECURITY_EVENT_NONE has no effect");
        break;

      case SECURITY_COMMAND_RECONNECT:
        WARN("Explicit security reconnect requested");
        security_reconnect();
        break;

      case SECURITY_COMMAND_PLAIN_TEXT_BINDING:
        PRINT_INFO("Plain text binding in progress..");
        security_exchange_keys(PLAIN_TEXT_KEY_SHARE_BINDING_REQUEST);
        break;

      case SECURITY_COMMAND_ECDH_BINDING:
        PRINT_INFO("ECDH binding in progress..");
        security_exchange_keys(ECDH_BINDING_REQUEST);
        break;

      case SECURITY_COMMAND_UNBIND:
        PRINT_INFO("Unbind in progress..");
        security_request_unbind();
        break;

      case SECURITY_COMMAND_INITIALIZE_SESSION:
        TRACE_SECURITY("Proceeding to session initialization");
        security_initialize_session();
        break;

      case SECURITY_COMMAND_RESET_SESSION:
        TRACE_SECURITY("Proceeding to reset session");
        security_initialize_session();
        break;

      case SECURITY_COMMAND_KILL_THREAD:
        if (security_initialized) {
          ret = cpc_close_endpoint(&security_ep);
          FATAL_ON(ret < 0);
          security_initialized = false;
        }
        security_set_state(SECURITY_STATE_NOT_READY);
        pthread_exit(NULL);
        break;

      default:
        BUG("Event doesn't exist");
        break;
    }
  }

  FATAL("Security thread ended");
  return NULL;
}

static void security_open_security_endpoint(void)
{
  int max_retries = 5;
  cpc_timeval_t timeout;
  int ret;

  timeout.seconds      = SECURITY_READ_TIMEOUT_SEC;
  timeout.microseconds = 0;

  do {
    ret = cpc_open_endpoint(lib_handle, &security_ep, SL_CPC_ENDPOINT_SECURITY, 1);
    if (ret == -EAGAIN) {
      max_retries--;
      sleep_s(1);
    }
  } while (ret == -EAGAIN && max_retries > 0);

  if (ret < 0) {
    FATAL("Failed to open the security endpoint (%d). Make sure encryption is enabled on the remote.", ret);
  }

  ret = cpc_set_endpoint_option(security_ep, CPC_OPTION_RX_TIMEOUT, &timeout, sizeof(timeout));
  if (ret < 0) {
    FATAL("Failed to set security endpoint option");
  }
}

static void security_reconnect(void)
{
  int ret;

  WARN("Processing security reconnection event");
  ret = cpc_close_endpoint(&security_ep);
  FATAL_ON(ret == -1);

  security_open_security_endpoint();
}
