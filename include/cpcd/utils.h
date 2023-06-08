/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Util
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

#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define sizeof_member(T, m) (sizeof(((T *)0)->m))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define FIELD_GET(mask, reg) (((reg) & (mask)) >> __bf_shf(mask))
#define FIELD_PREP(mask, val) (((val) << __bf_shf(mask)) & (mask))

#define min(x, y) ({        \
    __typeof__(x) _x = (x); \
    __typeof__(y) _y = (y); \
    _x < _y ? _x : _y;      \
  })

#define max(x, y) ({        \
    __typeof__(x) _x = (x); \
    __typeof__(y) _y = (y); \
    _x > _y ? _x : _y;      \
  })

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define PAD_TO_8_BYTES(x) (x + 8 - (x % 8))

static inline void* zalloc(size_t size)
{
  return calloc(1, size);
}

int recursive_mkdir(const char *dir, size_t len, const mode_t mode);

#endif
