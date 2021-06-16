/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Util
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

#ifndef UTILS_H
#define UTILS_H

#include <string.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define FIELD_GET(mask, reg) (((reg) & (mask)) >> __bf_shf(mask))
#define FIELD_PREP(mask, val) (((val) << __bf_shf(mask)) & (mask))

#define min(x, y) ({    \
    typeof(x) _x = (x); \
    typeof(y) _y = (y); \
    _x < _y ? _x : _y;  \
  })

#define max(x, y) ({    \
    typeof(x) _x = (x); \
    typeof(y) _y = (y); \
    _x > _y ? _x : _y;  \
  })

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static inline void *zalloc(size_t size)
{
  void *ptr = malloc(size);

  memset(ptr, 0, size);
  return ptr;
}

#endif
