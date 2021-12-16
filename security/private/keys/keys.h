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

#include <stddef.h>

#ifndef SECURITY_KEYS_H
#define SECURITY_KEYS_H

#include "mbedtls/ctr_drbg.h"

#define BINDING_KEY_LENGTH_BYTES         16
#define PUBLIC_KEY_LENGTH_BYTES          32
#define SESSION_KEY_LENGTH_BYTES         32
#define SESSION_ID_LENGTH_BYTES          8
#define SESSION_INIT_RANDOM_LENGTH_BYTES 64
#define SHA256_LENGTH_BYTES              32

extern mbedtls_ctr_drbg_context rng_context;

void security_keys_init(void);

void security_compute_session_key_and_id(uint8_t * random1, uint8_t * random2);

void security_load_binding_key_from_file(void);

uint8_t* security_get_binding_key(void);

#endif //SECURITY_KEYS_H
