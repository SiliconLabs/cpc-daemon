/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Xmodem
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

#ifndef XMODEM_H
#define XMODEM_H

#include <stdint.h>

/// Size of an XMODEM packet
#define XMODEM_DATA_SIZE              128

/// Start of Header
#define XMODEM_CMD_SOH                (0x01)
/// End of Transmission
#define XMODEM_CMD_EOT                (0x04)
/// Acknowledge
#define XMODEM_CMD_ACK                (0x06)
/// Not Acknowledge
#define XMODEM_CMD_NAK                (0x15)
/// Cancel
#define XMODEM_CMD_CAN                (0x18)
/// Ctrl+C
#define XMODEM_CMD_CTRL_C             (0x03)
/// ASCII 'C'
#define XMODEM_CMD_C                  (0x43)

typedef struct {
  uint8_t header;                   ///< Packet header (@ref XMODEM_CMD_SOH)
  uint8_t seq;                      ///< Packet sequence number
  uint8_t seq_neg;                  ///< Complement of packet sequence number
  uint8_t data[XMODEM_DATA_SIZE];   ///< Payload
  uint16_t crc;                     ///< CRC
} __attribute__((packed)) XmodemFrame_t;

#endif // XMODEM_H
