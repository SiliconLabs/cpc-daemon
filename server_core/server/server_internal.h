/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Internal
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

#ifndef SERVER_INTERNAL_H
#define SERVER_INTERNAL_H

#include <stdint.h>

#include "misc/sl_slist.h"

void server_push_data_to_core(uint8_t endpoint_number, const void *data, size_t data_len);

void server_tell_core_to_open_endpoint(uint8_t endpoint_number);

#endif //SERVER_INTERNAL_H
