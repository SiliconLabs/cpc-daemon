/*******************************************************************************
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Sleep functions
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

#ifndef SLEEP_H
#define SLEEP_H

#include <stdint.h>

/** Helpers around the nanosleep POSIX system call */

int sleep_us(uint32_t us);

static inline int sleep_ms(uint32_t ms)
{
  return sleep_us(ms * 1000);
}

int sleep_s(uint32_t s);

#endif /* SLEEP_H */
