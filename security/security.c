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

#define _GNU_SOURCE
#include <pthread.h>

#include "security.h"
#include "misc/config.h"
#include "misc/logging.h"
#include "server_core/server/server_ready_sync.h"
#include "security/private/thread/security_thread.h"

extern pthread_t security_thread;

bool security_session_initialized = false;

void security_init(void)
{
  int ret;

  if (config_use_encryption == false) {
    TRACE_SECURITY("Encryption is disabled");
    return;
  }

  ret = pthread_create(&security_thread, NULL, security_thread_func, NULL);
  FATAL_ON(ret != 0);

  ret = pthread_setname_np(security_thread, "security");
  FATAL_ON(ret != 0);

  TRACE_SECURITY("Thread created");
}
