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
  header_buf[0] = SLI_CPC_HDLC_FLAG_VAL;
  header_buf[1] = address;
  u16_to_le(length, header_buf + 2);
  header_buf[4] = control;

  if (compute_crc) {
    uint16_t crc;
    crc = sli_cpc_get_crc_sw(header_buf, SLI_CPC_HDLC_HEADER_SIZE);
    u16_to_le(crc, header_buf + SLI_CPC_HDLC_HEADER_SIZE);
  }
}

/***************************************************************************//**
 * @brief Extracts the payload size from a HDLC header
 *
 * @return
 *   The extracted payload size, or -1 if the header is invalid
 ******************************************************************************/
int hdlc_extract_payload_size(const uint8_t *header)
{
  if (header[SLI_CPC_HDLC_FLAG_POS] != SLI_CPC_HDLC_FLAG_VAL) {
    return -1;
  }

  if (sli_cpc_get_crc_sw(header, SLI_CPC_HDLC_HEADER_SIZE) != hdlc_get_hcs(header)) {
    return -1;
  }

  return (int) hdlc_get_length(header);
}
