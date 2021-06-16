/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Enum
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

#ifndef SL_ENUM_H
#define SL_ENUM_H

#define SL_ENUM(name) typedef uint8_t name; enum name##_enum
#define SL_ENUM_GENERIC(name, type) typedef type name; enum name##_enum

#endif //SL_ENUM_H
