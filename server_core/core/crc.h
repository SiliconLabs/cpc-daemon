/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - CRC
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

#ifndef CRC_H
#define CRC_H

#include <stdbool.h>
#include <stdint.h>

/***************************************************************************//**
 * Computes CRC-16 CCITT on given buffer. Software implementation.
 *
 * @param buffer Pointer to the buffer on which the CRC must be computed.
 * @param buffer_length Length of the buffer, in bytes.
 *
 * @return CRC value.
 ******************************************************************************/
uint16_t sli_cpc_get_crc_sw(const void* buffer, uint16_t buffer_length);

/***************************************************************************//**
 * Validates CRC-16 CCITT on given buffer. Software implementation.
 *
 * @param buffer Pointer to the buffer on which the CRC must be computed.
 * @param buffer_length Length of the buffer, in bytes.
 * @param expected_crc Expected CRC value.
 *
 * @return true if CRC matches. False otherwise.
 ******************************************************************************/
bool sli_cpc_validate_crc_sw(const void* buffer, uint16_t buffer_length, uint16_t expected_crc);

#endif //CRC_H
