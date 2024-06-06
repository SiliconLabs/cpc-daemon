/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Protocol With Secondary
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

#include "config.h"

#include "cpcd/logging.h"
#include "cpcd/utils.h"

#include "protocol.h"
#include "protocol_internal.h"

/// Implementation for protocol v4
static struct protocol_ops protocol_v4_ops = {
  .version              = 4,
  .parse_endpoint_state = parse_endpoint_state_v4,
  .is_opened            = is_endpoint_opened_v4,
  .is_encrypted         = is_endpoint_encrypted_v4,
  .connect              = connect_endpoint_v4,
  .terminate            = terminate_endpoint_v4,
};

/// Implementation for protocol v5
static struct protocol_ops protocol_v5_ops = {
  .version              = 5,
  .parse_endpoint_state = parse_endpoint_state_v5,
  .is_opened            = is_endpoint_opened_v5,
  .is_encrypted         = is_endpoint_encrypted_v4, // was not updated
  .connect              = connect_endpoint_v5,
  .disconnect           = disconnect_endpoint_v5,
  .terminate            = terminate_endpoint_v5,
#if defined(ENABLE_ENCRYPTION)
  .set_security_counters = set_security_counters_v5,
#endif
};

/***************************************************************************//**
 * Retrieve a protocol operation structure.
 ******************************************************************************/
struct protocol_ops* protocol_get(uint8_t version)
{
  switch (version) {
    case 4:
      return &protocol_v4_ops;
    case 5:
      return &protocol_v5_ops;
    default:
      WARN("Unsupported protocol version %d", version);
      return NULL;
  }
}

/***************************************************************************//**
 * Allocate structure to store callback context.
 ******************************************************************************/
struct protocol_callback_context* protocol_new_callback_context(void)
{
  struct protocol_callback_context *ctx;

  ctx = (struct protocol_callback_context*)zalloc(sizeof(*ctx));

  return ctx;
}

/***************************************************************************//**
 * Free structure allocated with `protocol_new_callback_context`.
 ******************************************************************************/
void protocol_free_callback_context(struct protocol_callback_context *ctx)
{
  free(ctx);
}
