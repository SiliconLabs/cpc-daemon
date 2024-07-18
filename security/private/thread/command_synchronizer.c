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

#include "config.h"

#include <pthread.h>

#include "cpcd/config.h"
#include "cpcd/logging.h"

#include "security/security.h"
#include "security/private/thread/command_synchronizer.h"

// Inter-thread command sending synchronization
static struct {
  sl_cpc_security_command_t command_type;
  pthread_cond_t            command_in_process_condition;
  pthread_mutex_t           command_in_progress_mutex;
} command_binary_synchronizer = { SECURITY_COMMAND_NONE,
                                  PTHREAD_COND_INITIALIZER,
                                  PTHREAD_MUTEX_INITIALIZER };

/*
 * Thread safe way of sending a command to the security thread.
 */
void security_post_command(sl_cpc_security_command_t command)
{
  int ret;

  if (config.use_encryption == false) {
    FATAL("Tried to send a security command when encryption is disabled");
  }

  // A condition is used in pair with a mutex to check against the condition's predicate
  // (i.e security_event_binary_synchronizer.event_type)
  pthread_mutex_lock(&command_binary_synchronizer.command_in_progress_mutex);
  {
    while (command_binary_synchronizer.command_type != SECURITY_COMMAND_NONE) {
      ret = pthread_cond_wait(&command_binary_synchronizer.command_in_process_condition,
                              &command_binary_synchronizer.command_in_progress_mutex);
      FATAL_ON(ret != 0);
    }

    // Here we know that no security event request is pending and have the lock to update it
    command_binary_synchronizer.command_type = command;

    // Kick the condition to notify the security thread that a event is requested
    ret = pthread_cond_signal(&command_binary_synchronizer.command_in_process_condition);
    FATAL_ON(ret != 0);
  }
  pthread_mutex_unlock(&command_binary_synchronizer.command_in_progress_mutex);
}

/*
 * Thread-safe way for the security thread to block until another thread
 * sends a command.
 */
sl_cpc_security_command_t security_wait_for_command(void)
{
  int ret;
  sl_cpc_security_command_t command;

  // A condition is used in pair with a mutex to check against the condition's predicate
  // (i.e security_event_binary_synchronizer.event_type)
  pthread_mutex_lock(&command_binary_synchronizer.command_in_progress_mutex);
  {
    // Wait until there is an event
    while (command_binary_synchronizer.command_type == SECURITY_COMMAND_NONE) {
      ret = pthread_cond_wait(&command_binary_synchronizer.command_in_process_condition,
                              &command_binary_synchronizer.command_in_progress_mutex);
      FATAL_ON(ret != 0);
    }

    command  = command_binary_synchronizer.command_type;

    // The event has been registered, kick the condition to let other sender thread(s) be able
    // to send another request right away
    command_binary_synchronizer.command_type = SECURITY_COMMAND_NONE;
    pthread_cond_signal(&command_binary_synchronizer.command_in_process_condition);
  }
  pthread_mutex_unlock(&command_binary_synchronizer.command_in_progress_mutex);

  return command;
}

void security_flush_pending_commands(void)
{
  sl_cpc_security_command_t pending_command;

  pthread_mutex_lock(&command_binary_synchronizer.command_in_progress_mutex);
  pending_command = command_binary_synchronizer.command_type;
  pthread_mutex_unlock(&command_binary_synchronizer.command_in_progress_mutex);

  if (pending_command != SECURITY_COMMAND_NONE) {
    security_wait_for_command();
  }
}
