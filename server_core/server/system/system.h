/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - System Endpoint
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

#ifndef EP_SYSTEM_H
#define EP_SYSTEM_H

#include "system_common.h"
#include "epoll.h"
#include "sl_slist.h"

#define CPC_EP_SYSTEM 0

typedef struct  {
  sl_slist_node_t node_commands;
  sl_cpc_system_cmd_t *command; // has to be malloc'ed
  void *on_final;
  uint8_t retry_count;
  uint32_t retry_timeout_us;
  sl_status_t error_status;
  uint8_t command_seq;
  epoll_private_data_t re_transmit_timer_private_data; //for epoll for timerfd
} sl_cpc_system_command_handle_t;

void sl_cpc_system_init(void);

/***************************************************************************//**
 * Unsolicited status callback
 *
 * @brief
 *   This callback is called when the PRIMARY receives an unsolicited propoperty-is PROP_LAST_STATUS
 *
 ******************************************************************************/
typedef void (*sl_cpc_system_unsolicited_status_callback_t) (sl_cpc_system_status_t status);

/***************************************************************************//**
 * Callback for the no-op command
 *
 * @brief
 *   This callback is called when the PRIMARY receives the reply from the SECONDARY
 *
 ******************************************************************************/
typedef void (*sl_cpc_system_noop_cmd_callback_t) (sl_cpc_system_command_handle_t *handle,
                                                   sl_status_t status);

/***************************************************************************//**
 * Callback for the reset command
 *
 * @brief
 *   This callback is called when the PRIMARY receives the reply from the SECONDARY
 *
 * @param
 *   [in] status
 *     The SECONDARY will return STATUS_OK if the reset will occur in the
 *     desired mode. STATUS_FAILURE will be returned otherwise.
 ******************************************************************************/
typedef void (*sl_cpc_system_reset_cmd_callback_t) (sl_cpc_system_command_handle_t *handle,
                                                    sl_status_t command_status,
                                                    sl_cpc_system_status_t reset_status);

/***************************************************************************//**
 * Callback for the property-get or set command
 *
 * @param
 *   [in] property_id
 *     The id of the property from the previously issued property-get/set
 *
 *   [in] property_value
 *     A pointer to the value returned by the SECONDARY. Has to be casted to an
 *     appropriate value in function of the property id.
 *
 *   [in] property_length
 *     The length of the property value in bytes.
 *
 ******************************************************************************/
typedef void (*sl_cpc_system_property_get_set_cmd_callback_t) (sl_cpc_system_command_handle_t *handle,
                                                               sl_cpc_property_id_t property_id,
                                                               void* property_value,
                                                               size_t property_length,
                                                               sl_status_t status);

/***************************************************************************//**
 * Send no-operation command query
 *
 * @brief
 *   This command can be seen like a ping command. Like its name implies, this
 *   command does nothing except generating a bidirectional transaction to
 *   assert the link is functional.
 ******************************************************************************/
void sl_cpc_system_cmd_noop(sl_cpc_system_noop_cmd_callback_t on_noop_reply,
                            uint8_t retry_count_max,
                            uint32_t retry_timeout_us);

/***************************************************************************//**
 * Sends a reset query
 ******************************************************************************/
void sl_cpc_system_cmd_reset(sl_cpc_system_reset_cmd_callback_t on_reset_reply,
                             uint8_t retry_count_max,
                             uint32_t retry_timeout_us);

/***************************************************************************//**
 * Sends a property-get query
 ******************************************************************************/
void sl_cpc_system_cmd_property_get(sl_cpc_system_property_get_set_cmd_callback_t on_property_get_reply,
                                    sl_cpc_property_id_t property_id,
                                    uint8_t retry_count_max,
                                    uint32_t retry_timeout_us);

/***************************************************************************//**
 * Sends a property-set query
 ******************************************************************************/
void sl_cpc_system_cmd_property_set(sl_cpc_system_property_get_set_cmd_callback_t on_property_set_reply,
                                    uint8_t retry_count_max,
                                    uint32_t retry_timeout_us,
                                    sl_cpc_property_id_t property_id,
                                    const void *value,
                                    size_t value_length);

/***************************************************************************//**
 * Registers an unsolicited prop last status callback
 ******************************************************************************/
void sl_cpc_system_register_unsolicited_prop_last_status_callback(sl_cpc_system_unsolicited_status_callback_t);

#endif
