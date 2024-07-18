/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Server Initialization Synchronization
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

#include "config.h"

#include <pthread.h>
#include <stdbool.h>

#include "cpcd/logging.h"

#include "server_core/server/server_ready_sync.h"

static struct {
  bool            is_ready;
  pthread_cond_t  is_ready_condition;
  pthread_mutex_t is_ready_mutex;
} server_ready_synchronizer = { false,
                                PTHREAD_COND_INITIALIZER,
                                PTHREAD_MUTEX_INITIALIZER };

void server_ready_post(void)
{
  int ret;

  pthread_mutex_lock(&server_ready_synchronizer.is_ready_mutex);
  {
    BUG_ON(server_ready_synchronizer.is_ready == true);

    server_ready_synchronizer.is_ready = true;

    ret = pthread_cond_signal(&server_ready_synchronizer.is_ready_condition);
    FATAL_ON(ret != 0);
  }
  pthread_mutex_unlock(&server_ready_synchronizer.is_ready_mutex);
}

void server_ready_wait(void)
{
  int ret;

  pthread_mutex_lock(&server_ready_synchronizer.is_ready_mutex);
  {
    while (server_ready_synchronizer.is_ready == false) {
      ret = pthread_cond_wait(&server_ready_synchronizer.is_ready_condition,
                              &server_ready_synchronizer.is_ready_mutex);
      FATAL_ON(ret != 0);
    }

    // Nothing to do with the predicate.
  }
  pthread_mutex_unlock(&server_ready_synchronizer.is_ready_mutex);
}
