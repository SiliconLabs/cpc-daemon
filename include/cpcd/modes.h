/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Daemon Running Mode
 *******************************************************************************
 * # License
 * <b>Copyright 2023 Silicon Laboratories Inc. www.silabs.com</b>
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

#ifndef CPCD_MODES_H
#define CPCD_MODES_H

#include <stdint.h>

#include "server_core/system_endpoint/system.h"

void run_binding_mode(void);

void run_firmware_update(void);

void run_normal_mode(void);

void run_uart_validation(void);
bool uart_validation_reset_requested(sl_cpc_system_status_t status);

#endif // CPCD_MODES_H
