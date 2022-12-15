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

#ifndef CORE_HDLC_H
#define CORE_HDLC_H

#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include "sl_cpc.h"
#include "misc/endianess.h"

#define SLI_CPC_HDLC_HEADER_SIZE      5U
#define SLI_CPC_HDLC_HEADER_RAW_SIZE  7U

#define SLI_CPC_HDLC_FLAG_VAL  0x14

#define SLI_CPC_HDLC_FLAG_POS    0
#define SLI_CPC_HDLC_ADDRESS_POS 1
#define SLI_CPC_HDLC_LENGTH_POS  2
#define SLI_CPC_HDLC_CONTROL_POS 4
#define SLI_CPC_HDLC_HCS_POS     5

#define SLI_CPC_HDLC_FRAME_TYPE_INFORMATION  0
#define SLI_CPC_HDLC_FRAME_TYPE_SUPERVISORY  2
#define SLI_CPC_HDLC_FRAME_TYPE_UNNUMBERED   3

#define SLI_CPC_HDLC_CONTROL_FRAME_TYPE_SHIFT          6
#define SLI_CPC_HDLC_CONTROL_P_F_SHIFT                 3
#define SLI_CPC_HDLC_CONTROL_SEQ_SHIFT                 4
#define SLI_CPC_HDLC_CONTROL_SUPERVISORY_FNCT_ID_SHIFT 4
#define SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_SHIFT     0

#define SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_MASK  0x3F

#define SLI_CPC_HDLC_ACK_SUPERVISORY_FUNCTION   0

#define SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_INFORMATION  0x00
#define SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_POLL_FINAL   0x04
#define SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_RESET_SEQ    0x31
#define SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_ACKNOWLEDGE  0x0E
#define SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_UNKNOWN      0xFF

#define SLI_CPC_HDLC_REJECT_SUPERVISORY_FUNCTION   1
#define SLI_CPC_HDLC_REJECT_PAYLOAD_SIZE  1

#define SLI_CPC_HDLC_FCS_SIZE 2

SL_ENUM(sl_cpc_reject_reason_t){
  HDLC_REJECT_NO_ERROR = 0,
  HDLC_REJECT_CHECKSUM_MISMATCH,
  HDLC_REJECT_SEQUENCE_MISMATCH,
  HDLC_REJECT_OUT_OF_MEMORY,
  HDLC_REJECT_SECURITY_ISSUE,
  HDLC_REJECT_UNREACHABLE_ENDPOINT,
  HDLC_REJECT_ERROR
};

typedef union {
  uint8_t bytes[2];
  uint16_t uint16;
}uint16_u;

/***************************************************************************//**
 * Gets HDLC header flag value.
 *
 * @param header_buf Pointer to the buffer that contains the HDLC header.
 *
 * @return HDLC header flag value.
 ******************************************************************************/
static inline uint8_t hdlc_get_flag(const uint8_t *header_buf)
{
  return header_buf[SLI_CPC_HDLC_FLAG_POS];
}

/***************************************************************************//**
 * Gets HDLC header address value.
 *
 * @param header_buf Pointer to the buffer that contains the HDLC header.
 *
 * @return HDLC header address value.
 ******************************************************************************/
static inline uint8_t hdlc_get_address(const uint8_t *header_buf)
{
  return header_buf[SLI_CPC_HDLC_ADDRESS_POS];
}

/***************************************************************************//**
 * Gets HDLC header payload length value.
 *
 * @param header_buf Pointer to the buffer that contains the HDLC header.
 *
 * @return HDLC header payload length value.
 ******************************************************************************/
static inline uint16_t hdlc_get_length(const uint8_t *header_buf)
{
  uint16_u u;

  u.bytes[0] = header_buf[SLI_CPC_HDLC_LENGTH_POS];
  u.bytes[1] = header_buf[SLI_CPC_HDLC_LENGTH_POS + 1];

  return le16_to_cpu(u.uint16);
}

/***************************************************************************//**
 * Gets HDLC header control value.
 *
 * @param header_buf Pointer to the buffer that contains the HDLC header.
 *
 * @return HDLC header control value.
 ******************************************************************************/
static inline uint8_t hdlc_get_control(const uint8_t *header_buf)
{
  return header_buf[SLI_CPC_HDLC_CONTROL_POS];
}

/***************************************************************************//**
 * Gets HDLC header HCS value.
 *
 * @param header_buf Pointer to the buffer that contains the HDLC header.
 *
 * @return HDLC header HCS value.
 ******************************************************************************/
static inline uint16_t hdlc_get_hcs(const uint8_t *header_buf)
{
  uint16_u u;

  u.bytes[0] = header_buf[SLI_CPC_HDLC_HCS_POS];
  u.bytes[1] = header_buf[SLI_CPC_HDLC_HCS_POS + 1];

  return le16_to_cpu(u.uint16);
}

/***************************************************************************//**
 * Gets HDLC payload FCS value.
 *
 * @param header_buf Pointer to the buffer that contains the HDLC header.
 *
 * @return HDLC payload FCS value.
 ******************************************************************************/
static inline uint16_t hdlc_get_fcs(const uint8_t *payload_buf, uint16_t payload_length)
{
  uint16_u u;

  u.bytes[0] = payload_buf[payload_length];
  u.bytes[1] = payload_buf[payload_length + 1];

  return le16_to_cpu(u.uint16);
}

/***************************************************************************//**
 * Gets HDLC frame type value.
 *
 * @param control Control value specified in HDLC header.
 *
 * @return HDLC frame type value.
 ******************************************************************************/
static inline uint8_t hdlc_get_frame_type(uint8_t control)
{
  uint8_t type = control >> SLI_CPC_HDLC_CONTROL_FRAME_TYPE_SHIFT;

  if (type == 1 || type == 0) {
    type = SLI_CPC_HDLC_FRAME_TYPE_INFORMATION;
  }

  return type;
}

/***************************************************************************//**
 * Gets HDLC frame SEQ value.
 *
 * @param control Control value specified in HDLC header.
 *
 * @return HDLC frame SEQ value.
 ******************************************************************************/
static inline uint8_t hdlc_get_seq(uint8_t control)
{
  return (control >> SLI_CPC_HDLC_CONTROL_SEQ_SHIFT) & 0x07;
}

/***************************************************************************//**
 * Gets HDLC frame ACK value.
 *
 * @param control Control value specified in HDLC header.
 *
 * @return HDLC frame ACK value.
 ******************************************************************************/
static inline uint8_t hdlc_get_ack(uint8_t control)
{
  return control & 0x07;
}

/***************************************************************************//**
 * Gets HDLC frame supervisory function value.
 *
 * @param control Control value specified in HDLC header.
 *
 * @return HDLC frame supervisory function value.
 ******************************************************************************/
static inline uint8_t hdlc_get_supervisory_function(uint8_t control)
{
  return (control >> SLI_CPC_HDLC_CONTROL_SUPERVISORY_FNCT_ID_SHIFT) & 0x03;
}

/***************************************************************************//**
 * Gets HDLC u-frame type.
 *
 * @param control Control value specified in HDLC header.
 *
 * @return HDLC u-frame type.
 ******************************************************************************/
static inline uint8_t hdlc_get_unumbered_type(uint8_t control)
{
  return (control >> SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_SHIFT) & SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_MASK;
}

/***************************************************************************//**
 * Gets HDLC u-frame poll/final bit.
 *
 * @param control Control value specified in HDLC header.
 *
 * @return true if HDLC frame poll/frame bit is set.
 ******************************************************************************/
static inline bool hdlc_is_poll_final(uint8_t control)
{
  if (control & (1 << SLI_CPC_HDLC_CONTROL_P_F_SHIFT)) {
    return true;
  }
  return false;
}

/***************************************************************************//**
 * Creates HDLC header.
 *
 * @param header_buf Pointer to the buffer where to write HDLC header.
 * @param address Address value.
 * @param length Length of payload.
 * @param control Control value.
 * @param compute_crc Set to true if this function shall compute the header
 *                    CRC (HCS). Set to false if DMA generates it automatically.
 ******************************************************************************/
void hdlc_create_header(uint8_t *header_buf,
                        uint8_t address,
                        uint16_t length,
                        uint8_t control,
                        bool compute_crc);

/***************************************************************************//**
 * Creates header control value data frame type.
 *
 * @param seq Sequence number.
 * @param ack ACK value.
 * @param poll_final activate P/F bit (Poll/Final)
 *
 * @return HDLC header control value.
 ******************************************************************************/
static inline uint8_t hdlc_create_control_data(uint8_t seq, uint8_t ack, bool poll_final)
{
  uint8_t control = SLI_CPC_HDLC_FRAME_TYPE_INFORMATION << SLI_CPC_HDLC_CONTROL_FRAME_TYPE_SHIFT;

  control |= (uint8_t)(seq << SLI_CPC_HDLC_CONTROL_SEQ_SHIFT);
  control |= ack;
  control |= (uint8_t)((uint8_t)poll_final << SLI_CPC_HDLC_CONTROL_P_F_SHIFT);

  return control;
}

/***************************************************************************//**
 * Creates header control value supervisory frame type.
 *
 * @param ack ACK value.
 * @param supervisory_function Supervisory function ID.
 *
 * @return HDLC header control value.
 ******************************************************************************/
static inline uint8_t hdlc_create_control_supervisory(uint8_t ack, uint8_t supervisory_function)
{
  uint8_t control = SLI_CPC_HDLC_FRAME_TYPE_SUPERVISORY << SLI_CPC_HDLC_CONTROL_FRAME_TYPE_SHIFT;

  control |= (uint8_t)(supervisory_function << SLI_CPC_HDLC_CONTROL_SUPERVISORY_FNCT_ID_SHIFT);
  control |= ack;

  return control;
}

/***************************************************************************//**
 * Creates header control value unumbered frame type.
 *
 * @return HDLC header control value.
 ******************************************************************************/
static inline uint8_t hdlc_create_control_unumbered(uint8_t type)
{
  uint8_t control = SLI_CPC_HDLC_FRAME_TYPE_UNNUMBERED << SLI_CPC_HDLC_CONTROL_FRAME_TYPE_SHIFT;

  control |= type << SLI_CPC_HDLC_CONTROL_UNNUMBERED_TYPE_SHIFT;

  return control;
}

/***************************************************************************//**
 * Update the ACK number in a frame's header.
 ******************************************************************************/
static inline void hdlc_set_control_ack(uint8_t *control,
                                        uint8_t ack)
{
  *control = (uint8_t)(*control & ~0x07);
  *control |= ack;
}

/** @} (end addtogroup cpc) */

#endif // SLI_CPC_HDLC_H
