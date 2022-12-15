/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Security Endpoint
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

#ifndef SECURITY_COMMAND_SYNCHRONIZER_H
#define SECURITY_COMMAND_SYNCHRONIZER_H

#include "security/security.h"

void security_post_command(sl_cpc_security_command_t command);

sl_cpc_security_command_t security_wait_for_command(void);

#endif //SECURITY_COMMAND_SYNCHRONIZER_H
