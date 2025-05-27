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

#include "config.h"

#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>

#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/version.h"

#include "cpcd/config.h"
#include "cpcd/logging.h"
#include "cpcd/sl_status.h"
#include "cpcd/utils.h"

#include "security/security.h"
#include "security/private/keys/keys.h"
#include "server_core/core/hdlc.h"

#if defined(UNIT_TESTING)
#include "server_core/core/core.h"
#endif

// MbedTLS minimal version required
#define MBEDTLS_VERSION_CHECK (MBEDTLS_VERSION_NUMBER < 0x02070000)
#if MBEDTLS_VERSION_CHECK
#error MbedTLS minimal version required >= 2.7.0
#endif

// MbedTLS backwards compatibility
#if (MBEDTLS_VERSION_MAJOR == 2)
#define MBEDTLS_PRIVATE(X) X
#define mbedtls_sha256 mbedtls_sha256_ret
#endif

#if !defined(SLI_CPC_SECURITY_NONCE_FRAME_COUNTER_RESET_VALUE)
#define SLI_CPC_SECURITY_NONCE_FRAME_COUNTER_RESET_VALUE 0
#endif

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
  uint32_t        count;
  uint8_t         session_id_primary[SESSION_ID_LENGTH_BYTES];
  uint8_t         session_id_secondary[SESSION_ID_LENGTH_BYTES];

#if defined(UNIT_TESTING)
// Emulate nonces as they should be on the remote device:
//  - remote_nonce_primary:   packets sent from host to secondary
//  - remote_nonce_secondary: packets sent from secondary to host
  uint8_t         remote_session_id_primary[SESSION_ID_LENGTH_BYTES];
  uint8_t         remote_session_id_secondary[SESSION_ID_LENGTH_BYTES];
#endif
} security_t;

static security_t security_ctx;
static bool security_session_reset_triggered;

sl_cpc_security_state_t security_state = SECURITY_STATE_NOT_READY;
pthread_mutex_t security_state_lock = PTHREAD_MUTEX_INITIALIZER;
static sl_cpc_security_on_state_change_t on_state_change_cb = NULL;

unsigned char ecdh_exchange_buffer[PUBLIC_KEY_LENGTH_BYTES];

// Since 2.10, mbedtls provides mbedtls_platform_zeroize in platform_util.h. If
// using an older version (like the one in Ubuntu 18.04), then provide a custom
// implementation.
#if (MBEDTLS_VERSION_NUMBER < 0x02100000)
static void *(*const volatile force_memset)(void *, int, size_t) = memset;
#define mbedtls_platform_zeroize(_buff, _size)  force_memset(_buff, 0x00, _size)
#else
#include "mbedtls/platform_util.h"
#endif

static void security_keys_init_ecdh(void);
static FILE* security_create_key_file(const char *filename);
static FILE* security_open_or_create_plaintext_binding_key_file(const char *filename);

static void security_ctx_init(security_t *sec)
{
  int ret;

  mbedtls_platform_zeroize(&sec->session_id_primary, sizeof(sec->session_id_primary));
  mbedtls_platform_zeroize(&sec->session_id_secondary, sizeof(sec->session_id_secondary));
#if defined(UNIT_TESTING)
  mbedtls_platform_zeroize(&sec->remote_session_id_primary, sizeof(sec->remote_session_id_primary));
  mbedtls_platform_zeroize(&sec->remote_session_id_secondary, sizeof(sec->remote_session_id_secondary));
#endif

  ret = pthread_mutex_lock(&sec->lock);
  FATAL_ON(ret != 0);

  sec->count = SLI_CPC_SECURITY_NONCE_FRAME_COUNTER_RESET_VALUE;

  ret = pthread_mutex_unlock(&sec->lock);
  FATAL_ON(ret != 0);
}

static void __security_set_session_id(uint8_t dest[SESSION_ID_LENGTH_BYTES], const uint8_t session_id[SESSION_ID_LENGTH_BYTES])
{
  memcpy(dest, session_id, SESSION_ID_LENGTH_BYTES);
}

static void security_nonce_xfer_init(security_t *sec,
                                     nonce_iv_t *iv,
                                     uint8_t session_id[SESSION_ID_LENGTH_BYTES],
                                     uint8_t endpoint_id,
                                     uint32_t frame_counter,
                                     bool primary_encrypt)
{
  int ret = pthread_mutex_lock(&sec->lock);
  FATAL_ON(ret != 0);

  if (primary_encrypt) {
    frame_counter |= NONCE_FRAME_COUNTER_PRIMARY_ENCRYPT_BITMASK;
  }

  // Initialize all fields of the initialization vector
  iv->endpoint_id = endpoint_id;
  u32_to_le(frame_counter, (uint8_t*)(&(iv->frame_counter)));
  memcpy(iv->session_id, session_id, SESSION_ID_LENGTH_BYTES);

  TRACE_SECURITY("Locking nonce. Endpoint: %d, counter: 0x%x",
                 endpoint_id, frame_counter);
}

static void security_nonce_xfer_finalize(security_t *sec, uint32_t *frame_counter, bool increment)
{
  int ret;

  if (increment) {
    // Secondary's architecture is Little Endian, so we need to make sure the
    // host uses the same way of storing the frame counter or there will be
    // mismatch on Big Endian architecture.
    if (frame_counter) {
      (*frame_counter)++;
    }

    // Keep track of the total number of invocations of the decrypt/crypt
    // method. The number of invocations with the same key is limited, going
    // beyond this limit decreases the robustness of AES-GCM and increase the
    // chances of an attacker to break authentication assurance.
    if (sec) {
      sec->count++;

      if (sec->count == NONCE_FRAME_COUNTER_MAX_VALUE) {
        // Set security in reset mode only if it's currently "initialized". This
        // is to prevent a scenario where it's first reset because of a TX packet,
        // and then reset again by an RX packet.
        if (security_get_state() == SECURITY_STATE_INITIALIZED) {
          // Keep track of the endpoint that triggered the endpoint
          security_session_reset_triggered = true;

          // make sure packets on user endpoins are blocked
          // while security session is being reset.
          security_set_state(SECURITY_STATE_RESETTING);

          // Notify the security thread to renegotiate a new session
          security_post_command(SECURITY_COMMAND_RESET_SESSION);
        }
      }
    }
  }

  TRACE_SECURITY("Frame counter%s incremented", increment ? "" : " NOT");

  if (sec) {
    ret = pthread_mutex_unlock(&sec->lock);
    FATAL_ON(ret != 0);
  }
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

void security_set_state(sl_cpc_security_state_t new_state)
{
  int ret = pthread_mutex_lock(&security_state_lock);
  FATAL_ON(ret != 0);

  sl_cpc_security_state_t current = security_state;
  security_state = new_state;

  if (on_state_change_cb != NULL) {
    on_state_change_cb(current, new_state);
  }

  ret = pthread_mutex_unlock(&security_state_lock);
  FATAL_ON(ret != 0);
}

void security_register_state_change_callback(sl_cpc_security_on_state_change_t func)
{
  int ret = pthread_mutex_lock(&security_state_lock);
  FATAL_ON(ret != 0);

  on_state_change_cb = func;

  ret = pthread_mutex_unlock(&security_state_lock);
  FATAL_ON(ret != 0);
}

void security_set_state_disabled(void)
{
  security_set_state(SECURITY_STATE_DISABLED);
}

bool security_session_has_reset(void)
{
  return security_session_reset_triggered;
}

void security_session_reset_clear_flag(void)
{
  security_session_reset_triggered = false;
}

mbedtls_ctr_drbg_context* security_keys_get_rng_context(void)
{
  FATAL_ON(rng_context_initialized == false);
  return &rng_context;
}

void security_keys_init(void)
{
  int ret;
  const char app_custom[] = "CPCD custom";

  // Perform MbedTLS runtime version check
  FATAL_ON(MBEDTLS_VERSION_CHECK);

  // Perform an initial self tests
#if defined(MBEDTLS_SELF_TEST)
  FATAL_ON(mbedtls_gcm_self_test(0) != 0);
  FATAL_ON(mbedtls_ctr_drbg_self_test(0) != 0);
  FATAL_ON(mbedtls_sha256_self_test(0) != 0);
  FATAL_ON(mbedtls_entropy_self_test(0) != 0);
#endif

  mbedtls_gcm_init(&gcm_context);
  mbedtls_entropy_init(&entropy_context);
  mbedtls_ctr_drbg_init(&rng_context);

  ret = mbedtls_ctr_drbg_seed(&rng_context,
                              mbedtls_entropy_func,
                              &entropy_context,
                              (const unsigned char*) app_custom,
                              sizeof(app_custom));
  FATAL_ON(ret != 0);

  ret = pthread_mutex_init(&security_ctx.lock, NULL);
  FATAL_ON(ret != 0);

  security_ctx_init(&security_ctx);

  rng_context_initialized = true;

  if (config.operation_mode == MODE_BINDING_ECDH) {
    security_keys_init_ecdh();
  }
}

void security_keys_reset(void)
{
  // Clear GCM context and underlying cipher sub-context
  // and reinit the context for next session
  mbedtls_gcm_free(&gcm_context);
  mbedtls_gcm_init(&gcm_context);

  security_ctx_init(&security_ctx);
}

static void security_keys_init_ecdh(void)
{
  int ret;

  mbedtls_mpi_init(&our_private_key);
  mbedtls_mpi_init(&shared_secret);
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&our_public_key);

  // Initialize context and generate keypair
  ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
  if (ret != 0) {
    FATAL("ECDH: Failed to load private key variable. ret=%d", ret);
  }

  TRACE_SECURITY("Generating keypair for ECDH exchange");
  ret = mbedtls_ecdh_gen_public(&grp, &our_private_key, &our_public_key, mbedtls_ctr_drbg_random, security_keys_get_rng_context());
  if (ret != 0) {
    FATAL("ECDH: Failed to generate public key. ret=%d", ret);
  }

  ret = mbedtls_mpi_write_binary(&our_public_key.MBEDTLS_PRIVATE(X), ecdh_exchange_buffer, sizeof(ecdh_exchange_buffer));
  if (ret != 0) {
    FATAL("ECDH: Failed to extract public key. ret=%d", ret);
  }
}

static FILE* security_create_key_file(const char *filename)
{
  FILE *fd;

  fd = fopen(filename, "w");
  if (fd == NULL) {
    FATAL("Failed to open key file in write mode. errno:%m");
  }

  if (chmod(filename, 0600) != 0) {
    FATAL("Failed to set key permissions. errno:%m");
  }

  return fd;
}

void security_keys_generate_shared_key(uint8_t *remote_public_key)
{
  int ret;
  FILE *fd;
  uint8_t *sha256_input;
  uint8_t *sha256_output;
  char *output_string;

  mbedtls_ecp_point_init(&peer_public_key);

  sha256_output = (uint8_t *)zalloc(PUBLIC_KEY_LENGTH_BYTES);
  sha256_input = (uint8_t *)zalloc(PUBLIC_KEY_LENGTH_BYTES);
  output_string = (char *)zalloc(BINDING_KEY_LENGTH_BYTES * 2 + 1);
  FATAL_SYSCALL_ON(sha256_output == NULL);
  FATAL_SYSCALL_ON(sha256_input == NULL);
  FATAL_SYSCALL_ON(output_string == NULL);
  char * p = output_string;

  ret = mbedtls_mpi_read_binary(&peer_public_key.MBEDTLS_PRIVATE(X), remote_public_key, PUBLIC_KEY_LENGTH_BYTES);
  if (ret != 0) {
    FATAL("ECDH: Failed to extract public key. ret=%d", ret);
  }

  ret = mbedtls_mpi_lset(&peer_public_key.MBEDTLS_PRIVATE(Z), 1);
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
  ret = mbedtls_sha256(sha256_input, PUBLIC_KEY_LENGTH_BYTES, sha256_output, 0);

  fd = security_create_key_file(config.binding_key_file);
  FATAL_ON(fd == NULL);

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
  mbedtls_platform_zeroize(output_string, BINDING_KEY_LENGTH_BYTES * 2 + 1);
  mbedtls_platform_zeroize(sha256_input, PUBLIC_KEY_LENGTH_BYTES);
  mbedtls_platform_zeroize(sha256_output, PUBLIC_KEY_LENGTH_BYTES);
  free(output_string);
  free(sha256_input);
  free(sha256_output);

  TRACE_SECURITY("Successfully generated the binding key. Stored it to provided file (%s)", config.binding_key_file);
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

  if (security_get_state() == SECURITY_STATE_RESETTING) {
    // if security is resetting, clear previous context and reset nonces
    security_keys_reset();
  }

  // Generate Session ID and Session Key
  {
    // Both devices will construct a string of bits:  Rand-3 = Rand-1[0:255] || Rand-2[0:255]
    memcpy(&random3[0], random1, half_random_len);
    memcpy(&random3[half_random_len], random2, half_random_len);

    /* Both devices will perform SHA256 on Rand-3. */
    ret = mbedtls_sha256(random3,
                         sizeof(random3),
                         sha256_random3,
                         0); //is not sha224
    FATAL_ON(ret != 0);

    // The resulting 32-byte number will be split into two 8-byte values as follows:
    //     Result = Session-ID-Host || Session-ID-NCP || Discarded data
    // As the session id in nonce is only 7 bytes, drop the last byte of each 8-byte value.
    __security_set_session_id(security_ctx.session_id_primary, &sha256_random3[0]);
    __security_set_session_id(security_ctx.session_id_secondary, &sha256_random3[SESSION_ID_LENGTH_BYTES + 1]);

#if defined(UNIT_TESTING)
    __security_set_session_id(security_ctx.remote_session_id_primary, &sha256_random3[0]);
    __security_set_session_id(security_ctx.remote_session_id_secondary, &sha256_random3[SESSION_ID_LENGTH_BYTES + 1]);
#endif

    // To generate the session key a second string of bits is constructed: Rand-4 = Rand-1[256:511] || Rand-2[256:511] || Binding Key[0:128]
    memcpy(&random4[0], &random1[half_random_len], half_random_len);
    memcpy(&random4[half_random_len], &random2[half_random_len], half_random_len);
    memcpy(&random4[2 * half_random_len], binding_key, BINDING_KEY_LENGTH_BYTES);

    // Both devices perform SHA256 on RAND-4
    // The resulting 256 bit number is then used as the session key
    ret = mbedtls_sha256(random4,
                         sizeof(random4),
                         session_key,
                         0); //is not sha224
    FATAL_ON(ret != 0);
  }

  // The session key is then used to encrypt all remaining communication
  ret = mbedtls_gcm_setkey(&gcm_context, MBEDTLS_CIPHER_ID_AES, session_key, SESSION_KEY_LENGTH_BYTES * 8);
  FATAL_ON(ret != 0);

  security_set_state(SECURITY_STATE_INITIALIZED);
}

static FILE* security_open_or_create_plaintext_binding_key_file(const char *filename)
{
  unsigned char key[BINDING_KEY_LENGTH_BYTES];
  FILE *file = fopen(filename, "r");
  int ret;

  if (file) {
    return file;
  }

  WARN("plaintext binding key file doesn't exist at '%s'. One will be generated "
       "for you but it's recommended to create a key manually and then pass it "
       "to cpcd. Refer to documentation for a how-to.",
       filename);

  ret = mbedtls_ctr_drbg_random(&rng_context, key, sizeof(key));
  FATAL_ON(ret != 0);

  file = security_create_key_file(filename);
  FATAL_ON(file == NULL);

  for (size_t i = 0; i < sizeof(key); i++) {
    ret = fprintf(file, "%.2x", key[i]);
    if (ret != 2) {
      fclose(file);
      FATAL("Incomplete write when generating plaintext binding key file");
    }
  }

  // reopen the file as read-only
  file = freopen(NULL, "r", file);
  FATAL_SYSCALL_ON(file == NULL);

  return file;
}

void security_load_binding_key_from_file(void)
{
  FILE* binding_key_file;
  char* line = NULL;
  size_t string_len = 0;
  size_t len = 0;
  ssize_t ret;
  size_t i;

  binding_key_file = security_open_or_create_plaintext_binding_key_file(config.binding_key_file);
  FATAL_ON(binding_key_file == NULL);

  ret = getline(&line, &len, binding_key_file);
  FATAL_SYSCALL_ON(ret < 0);

  ret = fclose(binding_key_file);
  FATAL_SYSCALL_ON(ret != 0);

  string_len = strlen(line);

  // Prune possible line feeds
  if (line[string_len - 1] == '\n' || line[string_len - 1] == '\r') {
    line[string_len - 1] = '\0';
    string_len--;
  }

  // Assert that the key is 128 bit long
  if (string_len != BINDING_KEY_LENGTH_BYTES * 2) {
    FATAL("The binding key \'%s\' : [%s] is %u bits long, should be %u bits long", config.binding_key_file, line, (unsigned int)(string_len * 4), BINDING_KEY_LENGTH_BYTES * 8);
  }

  // Make sure that all chars are hex symbols
  for (i = 0; i != BINDING_KEY_LENGTH_BYTES * 2; i++) {
    if (isxdigit(line[i]) == 0) {
      FATAL("Character number %u of the binding key is not a hexadecimal digit : %c", (unsigned int)i, line[i]);
    }
  }

  // Parse the binding key string into a binary array
  {
    unsigned chr;

    for (i = 0; i < BINDING_KEY_LENGTH_BYTES * 2; i += 2 ) {
      if (sscanf(&line[i], "%2x", &chr) != 1) {
        FATAL("The binding key \'%s\' : [%s] doesn't respect hexadecimal syntax", config.binding_key_file, line);
      }
      binding_key[i / 2] = (unsigned char)chr;
    }
  }

  // line was internally malloc'ed by getline()
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

sl_cpc_security_frame_t* security_encrypt_prepare_next_frame(sl_cpc_endpoint_t *ep)
{
  sl_cpc_security_frame_t *sec_frame = zalloc(sizeof(sl_cpc_security_frame_t));
  FATAL_ON(sec_frame == NULL);

  sec_frame->frame_counter = ep->frame_counter_tx;
  sec_frame->inc_enc_counter = true;
  security_nonce_xfer_finalize(NULL, &ep->frame_counter_tx, true);

  return sec_frame;
}

/*
 * Authenticate header and encrypt payload. Note that the payload buffer contains
 * unencrypted data when this function is called and will be filled with encrypted
 * data upon successful execution.
 * In the header, the length must include the tag lengthh and the CRC must be
 * computed already, otherwise the resulting tag will not be correct.
 */
sl_status_t __security_encrypt(sl_cpc_endpoint_t *ep, sl_cpc_security_frame_t *sec_frame,
                               const uint8_t *header, const size_t header_len,
                               const uint8_t *payload, const size_t payload_len,
                               uint8_t *output,
                               uint8_t *tag, const size_t tag_len)
{
  nonce_iv_t iv;
  int status;

  FATAL_ON(tag_len != TAG_LENGTH_BYTES);

  // set the endpoint in the nonce
  security_nonce_xfer_init(&security_ctx, &iv, security_ctx.session_id_primary, ep->id, sec_frame->frame_counter, true);

  status = mbedtls_gcm_crypt_and_tag(&gcm_context,
                                     MBEDTLS_GCM_ENCRYPT,
                                     payload_len,
                                     (uint8_t*)&iv,
                                     sizeof(iv),
                                     // additional data is the header, it's
                                     // authenticated but not encrypted
                                     header,
                                     header_len,
                                     payload, // The input buffer is the payload
                                     output,
                                     tag_len,
                                     tag);

  if (status == 0) {
    // only upon successful encryption increase frame counter
    security_nonce_xfer_finalize(&security_ctx, NULL, sec_frame->inc_enc_counter);

    // The encryption function can be called several times for the same frame in
    // case of retransmission, but the global encryption counter must only be
    // called once, for the very first encryption of a frame.
    if (sec_frame->inc_enc_counter) {
      sec_frame->inc_enc_counter = false;
    }

    return SL_STATUS_OK;
  }

  security_nonce_xfer_finalize(&security_ctx, NULL, false);

  // convert mbedtls error code to sl_status
  if (status == MBEDTLS_ERR_GCM_BAD_INPUT) {
    return SL_STATUS_INVALID_PARAMETER;
  } else {
    return SL_STATUS_FAIL;
  }
}

sl_status_t __security_decrypt(sl_cpc_endpoint_t *ep,
                               const uint8_t *header, const size_t header_len,
                               const uint8_t *payload, const size_t payload_len,
                               uint8_t *output,
                               const uint8_t *tag, const size_t tag_len)
{
  nonce_iv_t iv;
  int status;

  FATAL_ON(tag_len != TAG_LENGTH_BYTES);

  security_nonce_xfer_init(&security_ctx, &iv, security_ctx.session_id_secondary, ep->id, ep->frame_counter_rx, false);

  status = mbedtls_gcm_auth_decrypt(&gcm_context,
                                    payload_len,
                                    (uint8_t*)&iv,
                                    sizeof(iv),
                                    header,
                                    header_len,
                                    tag,
                                    tag_len,
                                    payload,
                                    output);

  if (status == 0) {
    security_nonce_xfer_finalize(&security_ctx, &ep->frame_counter_rx, true);

    return SL_STATUS_OK;
  }

  security_nonce_xfer_finalize(&security_ctx, &ep->frame_counter_rx, false);

  // convert mbedtls error code to sl_status
  if (status == MBEDTLS_ERR_GCM_BAD_INPUT) {
    return SL_STATUS_INVALID_PARAMETER;
  } else if (status == MBEDTLS_ERR_GCM_AUTH_FAILED) {
    return SL_STATUS_SECURITY_DECRYPT_ERROR;
  } else {
    return SL_STATUS_FAIL;
  }
}

#if defined(UNIT_TESTING)
sl_status_t __security_encrypt_secondary(sl_cpc_endpoint_t *ep,
                                         const uint8_t *header, const size_t header_len,
                                         const uint8_t *payload, const size_t payload_len,
                                         uint8_t *output,
                                         uint8_t *tag, const size_t tag_len)
{
  nonce_iv_t iv;
  int status;

  FATAL_ON(tag_len != TAG_LENGTH_BYTES);

  // set the endpoint in the nonce
  security_nonce_xfer_init(&security_ctx, &iv, security_ctx.remote_session_id_secondary, ep->id, ep->frame_counter_tx, false);

  status = mbedtls_gcm_crypt_and_tag(&gcm_context,
                                     MBEDTLS_GCM_ENCRYPT,
                                     payload_len,
                                     (uint8_t*)&iv,
                                     sizeof(iv),
                                     // additional data is the header, it's
                                     // authenticated but not encrypted
                                     header,
                                     header_len,
                                     payload, // The input buffer is the payload
                                     output,
                                     tag_len,
                                     tag);

  if (status == 0) {
    // only upon successful encryption increase frame counter
    security_nonce_xfer_finalize(&security_ctx, &ep->frame_counter_tx, true);

    return SL_STATUS_OK;
  }

  security_nonce_xfer_finalize(&security_ctx, &ep->frame_counter_tx, false);

  // convert mbedtls error code to sl_status
  if (status == MBEDTLS_ERR_GCM_BAD_INPUT) {
    return SL_STATUS_INVALID_PARAMETER;
  } else {
    return SL_STATUS_FAIL;
  }
}

sl_status_t __security_decrypt_secondary(sl_cpc_endpoint_t *ep,
                                         const uint8_t *header, const size_t header_len,
                                         const uint8_t *payload, const size_t payload_len,
                                         uint8_t *output,
                                         const uint8_t *tag, const size_t tag_len)
{
  nonce_iv_t iv;
  int status;

  FATAL_ON(tag_len != TAG_LENGTH_BYTES);

  security_nonce_xfer_init(&security_ctx, &iv, security_ctx.remote_session_id_primary, ep->id, ep->frame_counter_rx, true);

  status = mbedtls_gcm_auth_decrypt(&gcm_context,
                                    payload_len,
                                    (uint8_t*)&(iv),
                                    sizeof(iv),
                                    header,
                                    header_len,
                                    tag,
                                    tag_len,
                                    payload,
                                    output);

  if (status == 0) {
    security_nonce_xfer_finalize(&security_ctx, &ep->frame_counter_rx, true);

    return SL_STATUS_OK;
  }

  security_nonce_xfer_finalize(&security_ctx, &ep->frame_counter_rx, false);

  // convert mbedtls error code to sl_status
  if (status == MBEDTLS_ERR_GCM_BAD_INPUT) {
    return SL_STATUS_INVALID_PARAMETER;
  } else if (status == MBEDTLS_ERR_GCM_AUTH_FAILED) {
    return SL_STATUS_SECURITY_DECRYPT_ERROR;
  } else {
    return SL_STATUS_FAIL;
  }
}
#endif

void security_xfer_rollback(sl_cpc_endpoint_t *ep)
{
#if defined(ENABLE_ENCRYPTION)
  if (security_get_state() == SECURITY_STATE_INITIALIZED) {
    int ret;

    ret = pthread_mutex_lock(&security_ctx.lock);
    FATAL_ON(ret != 0);

    ep->frame_counter_rx--;
    security_ctx.count--;

    ret = pthread_mutex_unlock(&security_ctx.lock);
    FATAL_ON(ret != 0);

    TRACE_SECURITY("Rolled back frame counter on ep #%d, counter decremented", ep->id);
  }
#endif
}

#if defined(UNIT_TESTING)
void security_set_encryption_count(uint32_t value)
{
  int ret = pthread_mutex_lock(&security_ctx.lock);
  FATAL_ON(ret != 0);

  security_ctx.count = value;
  TRACE_SECURITY("Forcing total encryption count: %d", security_ctx.count);

  ret = pthread_mutex_unlock(&security_ctx.lock);
  FATAL_ON(ret != 0);
}

uint32_t security_get_encryption_count(void)
{
  int ret = pthread_mutex_lock(&security_ctx.lock);
  FATAL_ON(ret != 0);

  uint32_t count = security_ctx.count;

  ret = pthread_mutex_unlock(&security_ctx.lock);
  FATAL_ON(ret != 0);

  return count;
}

void security_get_nonce_session_id(uint8_t *buf, size_t len)
{
  BUG_ON(len != SESSION_ID_LENGTH_BYTES);

  memcpy(buf, security_ctx.session_id_primary, len);
}

void security_set_state_initializing(void)
{
  security_set_state(SECURITY_STATE_INITIALIZING);
}
#endif
