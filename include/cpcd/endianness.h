/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Endianess module
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

#ifndef ENDIANNESS_H
#define ENDIANNESS_H

#include <stdint.h>

static inline uint16_t u16_from_le(const uint8_t *p)
{
  return (uint16_t)(((uint16_t)(p[0]) << 0) | ((uint16_t)(p[1]) << 8));
}

static inline void u16_to_le(uint16_t x, uint8_t *p)
{
  p[0] = (uint8_t)(x >> 0);
  p[1] = (uint8_t)(x >> 8);
}

static inline uint32_t u32_from_le(const uint8_t *p)
{
  return (uint32_t)(((uint32_t)(p[0]) << 0) | ((uint32_t)(p[1]) << 8)
                    | ((uint32_t)(p[2]) << 16) | ((uint32_t)(p[3]) << 24));
}

static inline void u32_to_le(uint32_t x, uint8_t *p)
{
  p[0] = (uint8_t)(x >> 0);
  p[1] = (uint8_t)(x >> 8);
  p[2] = (uint8_t)(x >> 16);
  p[3] = (uint8_t)(x >> 24);
}

static inline uint64_t u64_from_le(const uint8_t *p)
{
  return (uint64_t)(((uint64_t)(p[0]) << 0) | ((uint64_t)(p[1]) << 8)
                    | ((uint64_t)(p[2]) << 16) | ((uint64_t)(p[3]) << 24)
                    | ((uint64_t)(p[4]) << 32) | ((uint64_t)(p[5]) << 40)
                    | ((uint64_t)(p[6]) << 48) | ((uint64_t)(p[7]) << 56));
}

static inline void u64_to_le(uint64_t x, uint8_t *p)
{
  p[0] = (uint8_t)(x >> 0);
  p[1] = (uint8_t)(x >> 8);
  p[2] = (uint8_t)(x >> 16);
  p[3] = (uint8_t)(x >> 24);
  p[4] = (uint8_t)(x >> 32);
  p[5] = (uint8_t)(x >> 40);
  p[6] = (uint8_t)(x >> 48);
  p[7] = (uint8_t)(x >> 56);
}

#endif
