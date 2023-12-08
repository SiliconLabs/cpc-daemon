/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Daemon Event Structure
 * @version 4.2.0
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

#ifndef CPCD_EVENT_H
#define CPCD_EVENT_H

#include "lib/sl_cpc.h"

typedef struct {
  cpc_event_type_t type;
  uint8_t endpoint_number;
  uint32_t payload_length;
  uint8_t payload[];
} cpcd_event_buffer_t;

#endif //CPCD_EVENT_H
