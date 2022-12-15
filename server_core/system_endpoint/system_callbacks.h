/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - System endpoint callback
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

#ifndef SYSTEM_CALLBACKS_H
#define SYSTEM_CALLBACKS_H

#include "server_core/system_endpoint/system.h"

#include <stdint.h>

typedef enum {
  SL_CPC_SYSTEM_OPEN_STEP_IDLE,
  SL_CPC_SYSTEM_OPEN_STEP_STATE_WAITING,
  SL_CPC_SYSTEM_OPEN_STEP_STATE_FETCHED,
  SL_CPC_SYSTEM_OPEN_STEP_ENCRYPTION_WAITING,
  SL_CPC_SYSTEM_OPEN_STEP_ENCRYPTION_FETCHED,
  SL_CPC_SYSTEM_OPEN_STEP_DONE,
} sl_cpc_system_open_step_t;

extern sl_cpc_system_open_step_t system_open_ep_step;

void sl_cpc_system_set_pending_connection(int fd);
bool sl_cpc_system_is_waiting_for_status_reply(void);

void reply_to_closing_endpoint_on_secondary_async_callback(sl_cpc_system_command_handle_t *handle,
                                                           sl_cpc_property_id_t property_id,
                                                           void* property_value,
                                                           size_t property_length,
                                                           sl_status_t status);

void reply_to_closing_endpoint_on_secondary_callback(sl_cpc_system_command_handle_t *handle,
                                                     sl_cpc_property_id_t property_id,
                                                     void* property_value,
                                                     size_t property_length,
                                                     sl_status_t status);

void property_get_single_endpoint_state_and_reply_to_pending_open_callback(sl_cpc_system_command_handle_t *handle,
                                                                           sl_cpc_property_id_t property_id,
                                                                           void* property_value,
                                                                           size_t property_length,
                                                                           sl_status_t status);

#if defined(ENABLE_ENCRYPTION)
void property_get_single_endpoint_encryption_state_and_reply_to_pending_open_callback(sl_cpc_system_command_handle_t *handle,
                                                                                      sl_cpc_property_id_t property_id,
                                                                                      void* property_value,
                                                                                      size_t property_length,
                                                                                      sl_status_t status);
#endif

void system_noop_cmd_callback_t (sl_cpc_system_command_handle_t *handle,
                                 sl_status_t status);

#endif //SYSTEM_CALLBACKS_H
