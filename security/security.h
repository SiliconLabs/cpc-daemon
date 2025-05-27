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

#ifndef SECURITY_PRIVATE_H
#define SECURITY_PRIVATE_H

#include "cpcd/security.h"

void security_set_state(sl_cpc_security_state_t new_state);

extern volatile bool security_session_initialized;

#if defined(UNIT_TESTING)
void security_set_encryption_count(uint32_t value);
uint32_t security_get_encryption_count(void);
void security_get_nonce_session_id(uint8_t *buf, size_t len);
void security_set_state_initializing(void);
#endif

#endif // SECURITY_PRIVATE_H
