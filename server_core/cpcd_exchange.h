/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Daemon Exchange Structure
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

#ifndef CPCD_EXCHANGE_H
#define CPCD_EXCHANGE_H

#include "lib/sl_cpc.h"
#include "misc/sl_status.h"

SL_ENUM_GENERIC(cpcd_exchange_type_t, uint8_t)
{
  EXCHANGE_ENDPOINT_STATUS_QUERY,
  EXCHANGE_OPEN_ENDPOINT_QUERY,
  EXCHANGE_MAX_WRITE_SIZE_QUERY,
  EXCHANGE_VERSION_QUERY,
  EXCHANGE_CLOSE_ENDPOINT_QUERY,
  EXCHANGE_SET_PID_QUERY
};

typedef struct {
  cpcd_exchange_type_t type;
  uint8_t endpoint_number;
  uint8_t payload[];
} cpcd_exchange_buffer_t;

#endif //CPCD_EXCHANGE_H
