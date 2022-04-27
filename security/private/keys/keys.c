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
#include "mbedtls/ecdh.h"
#include "mbedtls/pk.h"

#include "misc/config.h"
#include "misc/logging.h"
#include "misc/sl_status.h"
#include "security/security.h"
#include "security/private/keys/keys.h"
#include "server_core/core/hdlc.h"

static mbedtls_gcm_context gcm_context;
static mbedtls_entropy_context entropy_context;
static mbedtls_ecp_group grp;
static mbedtls_mpi shared_secret;
static mbedtls_mpi our_private_key;
static mbedtls_ecp_point peer_public_key, our_public_key;
static mbedtls_ctr_drbg_context rng_context;

static bool rng_context_initialized = false;
static uint8_t binding_key[BINDING_KEY_LENGTH_BYTES] = { 0 };

typedef struct __attribute__((packed)) {
  uint8_t endpoint_id;
  uint8_t session_id[7];
  uint32_t frame_counter;
} nonce_iv_t;

typedef struct {
  pthread_mutex_t lock;
  nonce_iv_t      iv;
} nonce_t;

static nonce_t nonce_primary;
static nonce_t nonce_secondary;

sl_cpc_security_state_t security_state = SECURITY_STATE_NOT_READY;
pthread_mutex_t security_state_lock = PTHREAD_MUTEX_INITIALIZER;
static void security_keys_init_ecdh(void);

unsigned char ecdh_exchange_buffer[PUBLIC_KEY_LENGTH_BYTES];

static void * (*const volatile force_memset)(void *, int, size_t) = memset;

static void security_nonce_init(nonce_t *nonce)
{
  /*
   * only setting frame_counter to zero matters, other attributes
   * will be initialized when the session id is computed, but do it
   * for completeness
   */
  nonce->iv.endpoint_id = 0;
  memset(&nonce->iv.session_id, 0x0, sizeof(nonce->iv.session_id));
  nonce->iv.frame_counter = 0;

  int ret = pthread_mutex_init(&nonce->lock, NULL);

  FATAL_ON(ret != 0);
}

static void security_nonce_set_session_id(nonce_t *nonce, const uint8_t *session_id, const size_t size)
{
  FATAL_ON(session_id == NULL);
  FATAL_ON(size > sizeof(nonce->iv.session_id));

  memcpy(nonce->iv.session_id, session_id, size);
}

static void security_nonce_xfer_init(nonce_t *nonce, const uint8_t endpoint_id)
{
  int ret = pthread_mutex_lock(&nonce->lock);
  FATAL_ON(ret != 0);

  nonce->iv.endpoint_id = endpoint_id;
  TRACE_SECURITY("Locking nonce. Endpoint: %d, counter: %d",
                 nonce->iv.endpoint_id, nonce->iv.frame_counter);
}

static void security_nonce_xfer_finalize(nonce_t *nonce, bool increment)
{
  int ret;

  nonce->iv.endpoint_id = 0;

  if (increment) {
    nonce->iv.frame_counter++;
  }

  TRACE_SECURITY("Unlocking nonce. frame counter%s incremented", increment ? "" : " NOT");

  ret = pthread_mutex_unlock(&nonce->lock);
  FATAL_ON(ret != 0);
}

sl_cpc_security_state_t security_get_state(void)
{
  sl_cpc_security_state_t local;
  int ret;

  ret = pthread_mutex_lock(&security_state_lock);
  FATAL_ON(ret != 0);

  local = security_state;

  ret = pthread_mutex_unlock(&security_state_lock);
  FATAL_ON(ret != 0);

  return local;
}

static void security_set_state(sl_cpc_security_state_t new_state)
{
  int ret = pthread_mutex_lock(&security_state_lock);
  FATAL_ON(ret != 0);

  security_state = new_state;

  ret = pthread_mutex_unlock(&security_state_lock);
  FATAL_ON(ret != 0);
}

void security_set_state_disabled(void)
{
  security_set_state(SECURITY_STATE_DISABLED);
}

mbedtls_ctr_drbg_context* security_keys_get_rng_context(void)
{
  FATAL_ON(rng_context_initialized == false);
  return &rng_context;
}

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

  security_nonce_init(&nonce_primary);
  security_nonce_init(&nonce_secondary);
  security_set_state(SECURITY_STATE_INITIALIZING);
  rng_context_initialized = true;

  if (config_operation_mode == MODE_BINDING_ECDH) {
    security_keys_init_ecdh();
  }
}

static void security_keys_init_ecdh(void)
{
  int ret;

  mbedtls_mpi_init(&our_private_key);
  mbedtls_mpi_init(&shared_secret);
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&our_public_key);

  /* Initialize context and generate keypair */
  ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
  if (ret != 0) {
    FATAL("ECDH: Failed to load private key variable. ret=%d", ret);
  }

  TRACE_SECURITY("Generating keypair for ECDH exchange");
  ret = mbedtls_ecdh_gen_public(&grp, &our_private_key, &our_public_key, mbedtls_ctr_drbg_random, security_keys_get_rng_context());
  if (ret != 0) {
    FATAL("ECDH: Failed to generate public key. ret=%d", ret);
  }

  ret = mbedtls_mpi_write_binary(&our_public_key.X, ecdh_exchange_buffer, sizeof(ecdh_exchange_buffer));
  if (ret != 0) {
    FATAL("ECDH: Failed to extract public key. ret=%d", ret);
  }
}

void security_keys_generate_shared_key(uint8_t *remote_public_key)
{
  int ret;
  FILE *fd;
  uint8_t *sha256_input;
  uint8_t *sha256_output;
  char *output_string;

  mbedtls_ecp_point_init(&peer_public_key);

  sha256_output = (uint8_t *)malloc(PUBLIC_KEY_LENGTH_BYTES);
  sha256_input = (uint8_t *)malloc(PUBLIC_KEY_LENGTH_BYTES);
  output_string = (char *)malloc(BINDING_KEY_LENGTH_BYTES * 2 + 1);
  FATAL_SYSCALL_ON(sha256_output == NULL);
  FATAL_SYSCALL_ON(sha256_input == NULL);
  FATAL_SYSCALL_ON(output_string == NULL);
  char * p = output_string;

  ret = mbedtls_mpi_read_binary(&peer_public_key.X, remote_public_key, PUBLIC_KEY_LENGTH_BYTES);
  if (ret != 0) {
    FATAL("ECDH: Failed to extract public key. ret=%d", ret);
  }

  ret = mbedtls_mpi_lset(&peer_public_key.Z, 1);
  if (ret != 0) {
    FATAL("ECDH: Failed to set Z. ret=%d", ret);
  }

  ret = mbedtls_ecdh_compute_shared(&grp, &shared_secret, &peer_public_key, &our_private_key, mbedtls_ctr_drbg_random, security_keys_get_rng_context());
  if ( ret != 0 ) {
    FATAL("ECHD: Failed to generate shared binding key. ret=%d", ret);
  }

  mbedtls_mpi_write_binary(&shared_secret, sha256_input, PUBLIC_KEY_LENGTH_BYTES);
  mbedtls_mpi_free(&shared_secret);

  // Hash and extract first 16 bytes as binding key
  ret = mbedtls_sha256_ret(sha256_input, PUBLIC_KEY_LENGTH_BYTES, sha256_output, 0);

  fd = fopen(config_binding_key_file, "w");
  if (fd == NULL) {
    FATAL("Failed to open key file in write mode. errno:%m");
  }

  // Store the binding key by truncating the first bytes from the sha256 output
  for (int i = 0; i < BINDING_KEY_LENGTH_BYTES; i++) {
    ret = sprintf(p, "%.2x", sha256_output[i]);
    FATAL_SYSCALL_ON(ret <= 0);
    p += ret;
  }
  output_string[BINDING_KEY_LENGTH_BYTES * 2] = '\0';

  if (fwrite(output_string, 1, BINDING_KEY_LENGTH_BYTES * 2 + 1, fd) != BINDING_KEY_LENGTH_BYTES * 2 + 1) {
    fclose(fd);
    FATAL("Failed to write into key file. errno:%m");
  }

  // Cleanup
  fclose(fd);
  force_memset(output_string, 0x00, BINDING_KEY_LENGTH_BYTES * 2 + 1);
  force_memset(sha256_input, 0x00, PUBLIC_KEY_LENGTH_BYTES);
  force_memset(sha256_output, 0x00, PUBLIC_KEY_LENGTH_BYTES);
  free(output_string);
  free(sha256_input);
  free(sha256_output);

  TRACE_SECURITY("Successfully generated the binding key. Stored it to provided file (%s)", config_binding_key_file);
}

uint8_t* security_keys_get_ecdh_public_key(void)
{
  return ecdh_exchange_buffer;
}

void security_compute_session_key_and_id(uint8_t * random1,
                                         uint8_t * random2)
{
  int ret;
  const size_t half_random_len = SESSION_INIT_RANDOM_LENGTH_BYTES / 2;
  uint8_t random3[SESSION_INIT_RANDOM_LENGTH_BYTES];
  uint8_t sha256_random3[SHA256_LENGTH_BYTES];
  uint8_t random4[2 * half_random_len + BINDING_KEY_LENGTH_BYTES];
  uint8_t session_key[SESSION_KEY_LENGTH_BYTES] = { 0 };

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

    /*
     * The resulting 32-byte number will be split into two 8-byte values as follows:
     *     Result = Session-ID-Host || Session-ID-NCP || Discarded data
     *
     * As the session id in nonce is only 7 bytes, drop the last byte of each 8-byte value.
     */
    security_nonce_set_session_id(&nonce_primary,
                                  &sha256_random3[0], SESSION_ID_LENGTH_BYTES);
    security_nonce_set_session_id(&nonce_secondary,
                                  &sha256_random3[SESSION_ID_LENGTH_BYTES + 1], SESSION_ID_LENGTH_BYTES);

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

  security_set_state(SECURITY_STATE_INITIALIZED);
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

/*
 * Return the extra buffer size that is needed after the payload to store
 * the security tag. Caller is responsible for allocating a frame that is large
 * enough to store both payload and security tag.
 */
size_t __security_encrypt_get_extra_buffer_size(void)
{
  return TAG_LENGTH_BYTES;
}

/*
 * Authenticate header and encrypt payload. Note that the payload buffer contains
 * unencrypted data when this function is called and will be filled with encrypted
 * data upon successful execution.
 * In the header, the length must include the tag lengthh and the CRC must be
 * computed already, otherwise the resulting tag will not be correct.
 */
sl_status_t __security_encrypt(const uint8_t *header, const size_t header_len,
                               const uint8_t *payload, const size_t payload_len,
                               uint8_t *output,
                               uint8_t *tag, const size_t tag_len)
{
  int status;

  FATAL_ON(tag_len != TAG_LENGTH_BYTES);

  /* set the endpoint in the nonce */
  security_nonce_xfer_init(&nonce_primary, hdlc_get_address(header));

  status = mbedtls_gcm_crypt_and_tag(&gcm_context,
                                     MBEDTLS_GCM_ENCRYPT,
                                     payload_len,
                                     (uint8_t*)&(nonce_primary.iv),
                                     sizeof(nonce_primary.iv),
                                     // additional data is the header, it's
                                     // authenticated but not encrypted
                                     header,
                                     header_len,
                                     payload, //The input buffer is the payload
                                     output,
                                     tag_len,
                                     tag);

  if (status == 0) {
    /* only upon successful encryption increase frame counter */
    security_nonce_xfer_finalize(&nonce_primary, true);

    return SL_STATUS_OK;
  }

  security_nonce_xfer_finalize(&nonce_primary, false);

  /* convert mbedtls error code to sl_status */
  if (status == MBEDTLS_ERR_GCM_BAD_INPUT) {
    return SL_STATUS_INVALID_PARAMETER;
  } else {
    return SL_STATUS_FAIL;
  }
}

sl_status_t __security_decrypt(const uint8_t *header, const size_t header_len,
                               const uint8_t *payload, const size_t payload_len,
                               uint8_t *output,
                               const uint8_t *tag, const size_t tag_len)
{
  int status;

  FATAL_ON(tag_len != TAG_LENGTH_BYTES);

  security_nonce_xfer_init(&nonce_secondary, hdlc_get_address(header));

  status = mbedtls_gcm_auth_decrypt(&gcm_context,
                                    payload_len,
                                    (uint8_t*)&(nonce_secondary.iv),
                                    sizeof(nonce_secondary.iv),
                                    header,
                                    header_len,
                                    tag,
                                    tag_len,
                                    payload,
                                    output);

  if (status == 0) {
    security_nonce_xfer_finalize(&nonce_secondary, true);

    return SL_STATUS_OK;
  }

  security_nonce_xfer_finalize(&nonce_secondary, false);

  /* convert mbedtls error code to sl_status */
  if (status == MBEDTLS_ERR_GCM_BAD_INPUT) {
    return SL_STATUS_INVALID_PARAMETER;
  } else if (status == MBEDTLS_ERR_GCM_AUTH_FAILED) {
    return SL_STATUS_SECURITY_DECRYPT_ERROR;
  } else {
    return SL_STATUS_FAIL;
  }
}

void security_drop_incoming_packet(void)
{
#if defined(ENABLE_ENCRYPTION)
  int ret;
  sl_cpc_security_state_t security_state = security_get_state();

  if (security_state == SECURITY_STATE_INITIALIZED) {
    ret = pthread_mutex_lock(&nonce_secondary.lock);
    FATAL_ON(ret != 0);

    nonce_secondary.iv.frame_counter++;

    TRACE_SECURITY("Dropped frame, counter incremented");

    ret = pthread_mutex_unlock(&nonce_secondary.lock);
    FATAL_ON(ret != 0);
  }
#endif
}
