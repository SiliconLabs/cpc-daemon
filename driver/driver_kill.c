/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) - Driver kill
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
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Definition of O_* constants */
#include <sys/eventfd.h>
#include <unistd.h>

#include "driver_kill.h"
#include "misc/logging.h"

static int kill_eventfd = -1;

int driver_kill_init(void)
{
  kill_eventfd = eventfd(0, //Start with 0 value
                         EFD_CLOEXEC);

  FATAL_ON(kill_eventfd == -1);

  return kill_eventfd;
}

void driver_kill_signal(void)
{
  ssize_t ret;
  const uint64_t event_value = 1; //doesn't matter what it is

  if (kill_eventfd == -1) {
    return;
  }

  ret = write(kill_eventfd, &event_value, sizeof(event_value));
  FATAL_ON(ret != sizeof(event_value));
}
