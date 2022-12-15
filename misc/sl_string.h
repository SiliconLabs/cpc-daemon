/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - String
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

#ifndef SL_STRING_H
#define SL_STRING_H

#include "sl_status.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * @addtogroup string String
 * @brief String functions
 * @{
 ******************************************************************************/

// -----------------------------------------------------------------------------
// Defines

// -----------------------------------------------------------------------------
// Prototypes

/*******************************************************************************
 * @brief
 *  Copy a string into a buffer.
 *  Normally, the complete source string including the '\0' termination will be
 *  copied to the destination.
 *  If the destination buffer doesn't have room to receive the
 *  complete source string, the source string will be truncated and the
 *  destination buffer will be '\0' terminated within the destination buffer.
 *
 * @param[in] dst       Destination buffer.
 *
 * @param[in] dst_size  The size of the destination buffer.
 *
 * @param[in] src       Source string.
 ******************************************************************************/
void sl_strcpy_s(char *dst, size_t dst_size, const char *src);

/*******************************************************************************
 * @brief
 *  Append the source string to the end of destination string.
 *  Normally, the complete source string including the '\0' termination will be
 *  appended to the destination, starting at the source strings '\0' termination.
 *  If the destination buffer has no room to receive the
 *  complete source string, the source string will be truncated and the
 *  destination '\0' terminated within the destination buffer.
 *
 * @param[in] dst       Destination string.
 *
 * @param[in] dst_size  The size of the destination string buffer.
 *
 * @param[in] src       Source string.
 ******************************************************************************/
void sl_strcat_s(char *dst, size_t dst_size, const char *src);

/*******************************************************************************
 * @brief
 *  Get the string length.
 *
 * @param[in] str       The string to get the length for.
 *
 * @return              String lenght.
 ******************************************************************************/
size_t sl_strlen(char *str);

/*******************************************************************************
 * @brief
 *  Get the string length, limited to given length.
 *
 * @param[in] str       The string to get the length for.
 *
 * @param[in] max_len   The input string is searched for at most max_lencharacters.
 *
 * @return              String lenght.
 ******************************************************************************/
size_t sl_strnlen(char *str, size_t max_len);

/*******************************************************************************
 * @brief
 *  Check if the string is empty.
 *
 * @param[in] str       The string to check.
 *
 * @return              true if string is empty or null, else return false.
 ******************************************************************************/
inline bool sl_str_is_empty(const char *str)
{
  return (str == NULL || *str == '\0');
}

/*******************************************************************************
 * @brief
 *  Compare two strings, ignoring case.
 *
 * @param[in] a         String to compare.
 *
 * @param[in] b         String to compare.
 *
 * @return              An integer greater than, or less than 0 if the strings
 *                      are not equal. 0 if the strings are equal.
 ******************************************************************************/
int sl_strcasecmp(char const *a, char const *b);

/** @} (end addtogroup string) */

#ifdef __cplusplus
}
#endif

#endif /* SL_STRING_H */
