/*******************************************************************************
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Sleep functions
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

#include "sleep.h"

#include <errno.h>  /* EINTR errno */
#include <time.h>   /* struct_timespec time_t nanosleep() */

int sleep_us(uint32_t us)
{
  int ret;
  struct timespec ts;
  /* Take the hot path if timeout is below one second */
  if (us < 1000000) {
    ts.tv_sec = 0;
    /* This is a safe cast: worst case scenario is the result gives 999999000,
     * which always fits in a long (>=i32) */
    ts.tv_nsec = (long)(us * 1000);
  } else {
    /* There is no portable way to get the maximum value of time_t, so we cast
     * and pray. */
    ts.tv_sec = (time_t)(us / 1000000);
    /* This is a safe cast: worst case scenario is the result gives 999'999'999,
     * which always fits in a long (>=i32) */
    ts.tv_nsec = (long)((us % 1000000) * 1000);
  }
  do {
    ret = nanosleep(&ts, &ts);
  } while (ret != 0 && errno == EINTR);
  return ret;
}

int sleep_s(uint32_t s)
{
  int ret;
  struct timespec ts;
  /* There is no portable way to get the maximum value of time_t, so we cast and
   * pray. */
  ts.tv_sec = (time_t)s;
  ts.tv_nsec = 0;
  do {
    ret = nanosleep(&ts, &ts);
  } while (ret != 0 && errno == EINTR);
  return ret;
}
