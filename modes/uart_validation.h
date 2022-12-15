/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - UART Validation Mode
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

#ifndef UART_VALIDATION_H
#define UART_VALIDATION_H

#include <stdint.h>

#include "server_core/system_endpoint/system.h"

void run_uart_validation(void);
bool uart_validation_reset_requested(sl_cpc_system_status_t status);

#endif //UART_VALIDATION_H
