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
#include <ctype.h>
#include <string.h>

#include "mbedtls/gcm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"

#include "misc/config.h"
#include "security/private/keys/keys.h"
#include "misc/logging.h"

static mbedtls_gcm_context gcm_context;
static mbedtls_entropy_context entropy_context;
mbedtls_ctr_drbg_context rng_context;

static uint8_t binding_key[BINDING_KEY_LENGTH_BYTES] = { 0 };
static uint8_t session_key[SESSION_KEY_LENGTH_BYTES] = { 0 };
static uint8_t session_id_primary[SESSION_ID_LENGTH_BYTES] = { 0 };
static uint8_t session_id_secondary[SESSION_ID_LENGTH_BYTES] = { 0 };

static void * (*const volatile force_memset)(void *, int, size_t) = memset;

void security_keys_init(void)
{
  const int verbose = 0;
  int ret;
  const char app_custom[] = "CPCD custom";

  /* Perform an initial self tests */
  FATAL_ON(mbedtls_gcm_self_test(verbose) != 0);
  FATAL_ON(mbedtls_ctr_drbg_self_test(verbose) != 0);
  FATAL_ON(mbedtls_sha256_self_test(verbose) != 0);
  FATAL_ON(mbedtls_entropy_self_test(verbose) != 0);

  mbedtls_gcm_init(&gcm_context);
  mbedtls_entropy_init(&entropy_context);
  mbedtls_ctr_drbg_init(&rng_context);

  ret = mbedtls_ctr_drbg_seed(&rng_context,
                              mbedtls_entropy_func,
                              &entropy_context,
                              (const unsigned char*) app_custom,
                              sizeof(app_custom));

  FATAL_ON(ret != 0);
}

void security_compute_session_key_and_id(uint8_t * random1,
                                         uint8_t * random2)
{
  int ret;
  const size_t half_random_len = SESSION_INIT_RANDOM_LENGTH_BYTES / 2;
  uint8_t random3[SESSION_INIT_RANDOM_LENGTH_BYTES];
  uint8_t sha256_random3[SHA256_LENGTH_BYTES];
  uint8_t random4[2 * half_random_len + BINDING_KEY_LENGTH_BYTES];

  /* Generate Session ID and Session Key */
  {
    /* Both devices will construct a string of bits:  Rand-3 = Rand-1[0:255] || Rand-2[0:255] */
    memcpy(&random3[0], random1, half_random_len);
    memcpy(&random3[half_random_len], random2, half_random_len);

    /* Both devices will perform SHA256 on Rand-3. */
    ret = mbedtls_sha256_ret(random3,
                             sizeof(random3),
                             sha256_random3,
                             0); //is not sha224
    FATAL_ON(ret != 0);

    /* The resulting 32-byte number will be split into two 8-byte values as follows: Result = Session-ID-Host || Session-ID-NCP || Discarded data */
    memcpy(session_id_primary, &sha256_random3[0], SESSION_ID_LENGTH_BYTES);
    memcpy(session_id_secondary, &sha256_random3[SESSION_ID_LENGTH_BYTES], SESSION_ID_LENGTH_BYTES);

    /* To generate the session key a second string of bits is constructed: Rand-4 = Rand-1[256:511] || Rand-2[256:511] || Binding Key[0:128] */
    memcpy(&random4[0], &random1[half_random_len], half_random_len);
    memcpy(&random4[half_random_len], &random2[half_random_len], half_random_len);
    memcpy(&random4[2 * half_random_len], binding_key, BINDING_KEY_LENGTH_BYTES);

    /* Both devices perform SHA256 on RAND-4
     * The resulting 256 bit number is then used as the session key */
    ret = mbedtls_sha256_ret(random4,
                             sizeof(random4),
                             session_key,
                             0); //is not sha224
    FATAL_ON(ret != 0);
  }

  /* Now that the session initialization process is completed and the session_key computed, the binding_key is not needed anymore. */
  force_memset(binding_key, 0x00, BINDING_KEY_LENGTH_BYTES);

  /* The session key is then used to encrypt all remaining communication */
  ret = mbedtls_gcm_setkey(&gcm_context, MBEDTLS_CIPHER_ID_AES, session_key, SESSION_KEY_LENGTH_BYTES * 8);
  FATAL_ON(ret != 0);
}

void security_load_binding_key_from_file(void)
{
  FILE* binding_key_file;
  char* line = NULL;
  size_t len = 0;
  ssize_t ret;
  size_t string_len;
  size_t i;

  /* The presence and read access of config_binding_key_file has already been checked
   * in the function 'config_validate_configuration' */
  binding_key_file = fopen(config_binding_key_file, "r");
  FATAL_ON(binding_key_file == NULL);

  ret = getline(&line, &len, binding_key_file);
  FATAL_SYSCALL_ON(ret < 0);

  ret = fclose(binding_key_file);
  FATAL_SYSCALL_ON(ret != 0);

  string_len = strlen(line);

  /* Prune possible line feeds */
  if (line[string_len - 1] == '\n' || line[string_len - 1] == '\r') {
    line[string_len - 1] = '\0';
    string_len--;
  }

  /* Assert that the key is 128 bit long */
  if (string_len != BINDING_KEY_LENGTH_BYTES * 2) {
    FATAL("The binding key \'%s\' : [%s] is %u bits long, should be %u bits long", config_binding_key_file, line, (unsigned int)(string_len * 4), BINDING_KEY_LENGTH_BYTES * 8);
  }

  /* Make sure that all chars are hex symbols */
  for (i = 0; i != BINDING_KEY_LENGTH_BYTES * 2; i++) {
    if (isxdigit(line[i]) == 0) {
      FATAL("Character number %u of the binding key is not a hexadecimal digit : %c", (unsigned int)i, line[i]);
    }
  }

  /* Parse the binding key string into a binary array*/
  {
    size_t i;
    unsigned chr;

    for (i = 0; i < BINDING_KEY_LENGTH_BYTES * 2; i += 2 ) {
      if (sscanf(&line[i], "%2x", &chr) != 1) {
        FATAL("The binding key \'%s\' : [%s] doesn't respect hexadecimal syntax", config_binding_key_file, line);
      }
      binding_key[i / 2] = (unsigned char)chr;
    }
  }

  /* line was internally malloc'ed by getline() */
  free(line);

  TRACE_SECURITY("Loaded valid binding key");
}

uint8_t* security_get_binding_key(void)
{
  return binding_key;
}
