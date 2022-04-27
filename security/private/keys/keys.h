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

#include <pthread.h>
#include "mbedtls/ctr_drbg.h"

#define BINDING_KEY_LENGTH_BYTES         16
#define PUBLIC_KEY_LENGTH_BYTES          32
#define SESSION_KEY_LENGTH_BYTES         32
#define SESSION_ID_LENGTH_BYTES          7
#define SESSION_INIT_RANDOM_LENGTH_BYTES 64
#define SHA256_LENGTH_BYTES              32
#define TAG_LENGTH_BYTES                 8

void security_keys_init(void);

void security_compute_session_key_and_id(uint8_t * random1, uint8_t * random2);

uint8_t* security_keys_get_ecdh_public_key(void);

void security_load_binding_key_from_file(void);

void security_set_state_disabled(void);
void security_keys_generate_shared_key(uint8_t *peer_public_key);

mbedtls_ctr_drbg_context* security_keys_get_rng_context(void);

uint8_t* security_get_binding_key(void);

size_t __security_encrypt_get_extra_buffer_size(void);

sl_status_t __security_encrypt(const uint8_t *header, const size_t header_len,
                               const uint8_t *payload, const size_t payload_len,
                               uint8_t *output,
                               uint8_t *tag, const size_t tag_len);

sl_status_t __security_decrypt(const uint8_t *header, const size_t header_len,
                               const uint8_t *payload, const size_t payload_len,
                               uint8_t *output,
                               const uint8_t *tag, const size_t tag_len);
#endif //SECURITY_KEYS_H
