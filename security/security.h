/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Security Endpoint
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

#ifndef SECURITY_H
#define SECURITY_H

#include <stdbool.h>

/***************************************************************************//**
 * Initialize the security endpoint
 ******************************************************************************/
void security_init(void);

typedef enum {
  SECURITY_COMMAND_NONE,
  SECURITY_COMMAND_RECONNECT,
  SECURITY_COMMAND_PLAIN_TEXT_BINDING,
  SECURITY_COMMAND_INITIALIZE_SESSION
}sl_cpc_security_command_t;

/***************************************************************************//**
 * Send a security command
 ******************************************************************************/
void security_post_command(sl_cpc_security_command_t event);

extern bool security_session_initialized;

#endif //SECURITY_H
