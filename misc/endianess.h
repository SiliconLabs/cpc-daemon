/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Endianess module
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

#ifndef ENDIANESS_H
#define ENDIANESS_H

#include <stdint.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __swap_le64(x) (x)
#define __swap_le32(x) (x)
#define __swap_le16(x) (x)
#define __swap_be64(x) __builtin_bswap64(x)
#define __swap_be32(x) __builtin_bswap32(x)
#define __swap_be16(x) __builtin_bswap16(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __swap_le64(x) __builtin_bswap64(x)
#define __swap_le32(x) __builtin_bswap32(x)
#define __swap_le16(x) __builtin_bswap16(x)
#define __swap_be64(x) (x)
#define __swap_be32(x) (x)
#define __swap_be16(x) (x)
#else
#error "Unsupported endianness"
#endif

static inline uint64_t cpu_to_le64(uint64_t val)
{
  return __swap_le64(val);
}

static inline uint64_t le64_to_cpu(uint64_t val)
{
  return __swap_le64(val);
}

static inline uint32_t cpu_to_le32(uint32_t val)
{
  return __swap_le32(val);
}

static inline uint32_t le32_to_cpu(uint32_t val)
{
  return __swap_le32(val);
}

static inline uint16_t cpu_to_le16(uint16_t val)
{
  return __swap_le16(val);
}

static inline uint16_t le16_to_cpu(uint16_t val)
{
  return __swap_le16(val);
}

static inline uint64_t cpu_to_be64(uint64_t val)
{
  return __swap_be64(val);
}

static inline uint64_t be64_to_cpu(uint64_t val)
{
  return __swap_be64(val);
}

static inline uint32_t cpu_to_be32(uint32_t val)
{
  return __swap_be32(val);
}

static inline uint32_t be32_to_cpu(uint32_t val)
{
  return __swap_be32(val);
}

static inline uint16_t cpu_to_be16(uint16_t val)
{
  return __swap_be16(val);
}

static inline uint16_t be16_to_cpu(uint16_t val)
{
  return __swap_be16(val);
}

static inline void cpu_to_le64s(uint64_t *val)
{
  *val = cpu_to_le64(*val);
}

static inline void le64_to_cpus(uint64_t *val)
{
  *val = le64_to_cpu(*val);
}

static inline void cpu_to_le32s(uint32_t *val)
{
  *val = cpu_to_le32(*val);
}

static inline void le32_to_cpus(uint32_t *val)
{
  *val = le32_to_cpu(*val);
}

static inline void cpu_to_le16s(uint16_t *val)
{
  *val = cpu_to_le16(*val);
}

static inline void le16_to_cpus(uint16_t *val)
{
  *val = le16_to_cpu(*val);
}

static inline void cpu_to_be64s(uint64_t *val)
{
  *val = cpu_to_be64(*val);
}

static inline void be64_to_cpus(uint64_t *val)
{
  *val = be64_to_cpu(*val);
}

static inline void cpu_to_be32s(uint32_t *val)
{
  *val = cpu_to_be32(*val);
}

static inline void be32_to_cpus(uint32_t *val)
{
  *val = be32_to_cpu(*val);
}

static inline void cpu_to_be16s(uint16_t *val)
{
  *val = cpu_to_be16(*val);
}

static inline void be16_to_cpus(uint16_t *val)
{
  *val = be16_to_cpu(*val);
}

#define cpu_to_le64p(val) cpu_to_le64(*(val))
#define le64_to_cpup(val) le64_to_cpu(*(val))
#define cpu_to_le32p(val) cpu_to_le32(*(val))
#define le32_to_cpup(val) le32_to_cpu(*(val))
#define cpu_to_le16p(val) cpu_to_le16(*(val))
#define le16_to_cpup(val) le16_to_cpu(*(val))

#endif
