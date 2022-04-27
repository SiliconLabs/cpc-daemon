/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Security Endpoint
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

#include <stdbool.h>

#include "misc/config.h"
#include "misc/logging.h"
#include "server_core/server/server_ready_sync.h"
#include "security/private/thread/security_thread.h"
#include "security/private/thread/command_synchronizer.h"
#include "security/private/keys/keys.h"
#include "security/private/protocol/protocol.h"
#include "security/security.h"

/* Library handles */
static cpc_handle_t lib_handle;

cpc_endpoint_t security_ep;

bool need_reconnect = false;
bool security_initialized = false;

#define SECURITY_READ_TIMEOUT_SEC 10

static void security_open_security_endpoint(void);
static void security_reconnect(void);

void* security_thread_func(void* param)
{
  (void)param;
  int ret;

  FATAL_ON(config_operation_mode == MODE_BINDING_UNKNOWN);

  /* The server can take time to be up; try to to load the key first
   * to crash early if its bad. */
  if (config_operation_mode != MODE_BINDING_ECDH && config_operation_mode != MODE_BINDING_UNBIND) {
    security_load_binding_key_from_file();
  }

  security_keys_init();

  /* Block until the server is up and running */
  server_ready_wait();

  ret = cpc_init(&lib_handle, config_instance_name, false, NULL);
  FATAL_ON(ret < 0);

  security_open_security_endpoint();

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
        TRACE_SECURITY("Processing security plain text binding event");
        security_exchange_plain_text_binding_key(security_get_binding_key());
        if (need_reconnect) {
          security_reconnect();
        }
        break;

      case SECURITY_COMMAND_ECDH_BINDING:
        TRACE_SECURITY("Processing ECDH binding event");
        security_exchange_ecdh_binding_key();
        if (need_reconnect) {
          security_reconnect();
        }
        break;

      case SECURITY_COMMAND_UNBIND:
        TRACE_SECURITY("Processing unbind event");
        security_request_unbind();
        if (need_reconnect) {
          security_reconnect();
        }
        break;

      case SECURITY_COMMAND_INITIALIZE_SESSION:
        TRACE_SECURITY("Proceeding to session initialization");
        security_initialize_session();
        break;

      case SECURITY_COMMAND_KILL_THREAD:
        pthread_exit(0);
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
  struct timeval timeout;
  int ret;

  timeout.tv_sec = SECURITY_READ_TIMEOUT_SEC;
  timeout.tv_usec = 0;

  ret = cpc_open_endpoint(lib_handle, &security_ep, SL_CPC_ENDPOINT_SECURITY, 1);
  if (ret < 0) {
    FATAL("Failed to open the security endpoint. Make sure encryption is enabled on the remote.");
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

  need_reconnect = false;
}
