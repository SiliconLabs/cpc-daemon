/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) - Driver kill
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

#include <fcntl.h>              // Definition of O_* constants
#include <sys/eventfd.h>
#include <unistd.h>

#include <pthread.h>

#include "cpcd/logging.h"

#include "driver_kill.h"

static void (*kill_callback)(void) = NULL;

void driver_kill_init(void (*driver_kill_callback)(void))
{
  if (kill_callback == NULL) {
    kill_callback = (void (*)(void))driver_kill_callback;
  }
}

void driver_kill(void)
{
  if (kill_callback != NULL) {
    kill_callback();
  }
}
