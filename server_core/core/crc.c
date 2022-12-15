/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - CRC
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

#include "crc.h"

static uint16_t sli_cpc_compute_crc16(uint8_t new_byte, uint16_t prev_result);

/***************************************************************************//**
 * Computes CRC-16 CCITT (XMODEM) on given buffer. Software implementation.
 ******************************************************************************/
uint16_t sli_cpc_get_crc_sw(const void* buffer, uint16_t buffer_length)
{
  uint16_t i;
  uint16_t crc = 0;

  for (i = 0; i < buffer_length; i++) {
    crc = sli_cpc_compute_crc16((uint8_t)((uint8_t *)buffer)[i], crc);
  }

  return crc;
}

/***************************************************************************//**
 * Validates CRC-16 CCITT (XMODEM) on given buffer. Software implementation.
 ******************************************************************************/
bool sli_cpc_validate_crc_sw(const void* buffer, uint16_t buffer_length, uint16_t expected_crc)
{
  uint16_t computed_crc;

  computed_crc = sli_cpc_get_crc_sw(buffer, buffer_length);

  return (computed_crc == expected_crc);
}

static uint16_t sli_cpc_compute_crc16(uint8_t new_byte, uint16_t prev_result)
{
  prev_result = ((uint16_t) (prev_result >> 8)) | ((uint16_t) (prev_result << 8));
  prev_result = (uint16_t)(prev_result ^ new_byte);
  prev_result = (uint16_t) (prev_result ^ (prev_result & 0xff) >> 4);
  prev_result ^= (uint16_t) (((uint16_t) (prev_result << 8)) << 4);
  prev_result = (uint16_t) (prev_result ^ ( ((uint8_t) (((uint8_t) (prev_result & 0xff)) << 5))
                                            | ((uint16_t) ((uint16_t) ((uint8_t) (((uint8_t) (prev_result & 0xff)) >> 3)) << 8))));

  return prev_result;
}
