/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Server
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

#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <stdbool.h>

#include "server_core/cpcd_exchange.h"

void server_init(void);

void server_open_endpoint(uint8_t endpoint_number);
void server_close_endpoint(uint8_t endpoint_number, bool error);

void server_push_data_to_endpoint(uint8_t endpoint_number, const uint8_t* data, size_t data_len);
void server_process_pending_connections(void);
bool server_is_endpoint_open(uint8_t endpoint_number);

bool server_listener_list_empty(uint8_t endpoint_number);

void server_notify_connected_libs_of_secondary_reset(void);

#endif
