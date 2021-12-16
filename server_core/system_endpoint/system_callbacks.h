/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - System endpoint callback
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

#ifndef SYSTEM_CALLBACKS_H
#define SYSTEM_CALLBACKS_H

#include "server_core/system_endpoint/system.h"

void sl_cpc_system_set_pending_connection(int fd);

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

void system_noop_cmd_callback_t (sl_cpc_system_command_handle_t *handle,
                                 sl_status_t status);

#endif //SYSTEM_CALLBACKS_H
