/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - HDLC
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

#include "hdlc.h"
#include "crc.h"

void hdlc_create_header(uint8_t *header_buf,
                        uint8_t address,
                        uint16_t length,
                        uint8_t control,
                        bool compute_crc)
{
  uint16_u length_union;

  length_union.uint16 = cpu_to_le16(length);

  header_buf[0] = SLI_CPC_HDLC_FLAG_VAL;
  header_buf[1] = address;
  header_buf[2] = length_union.bytes[0];
  header_buf[3] = length_union.bytes[1];
  header_buf[4] = control;

  if (compute_crc) {
    uint16_u hcs_union;

    hcs_union.uint16 = cpu_to_le16(sli_cpc_get_crc_sw(header_buf, SLI_CPC_HDLC_HEADER_SIZE));

    header_buf[5] = hcs_union.bytes[0];
    header_buf[6] = hcs_union.bytes[1];
  }
}
