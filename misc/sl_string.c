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

#include "sl_string.h"
#include <stdint.h>
#include <ctype.h>

/*******************************************************************************
 **************************   GLOBAL FUNCTIONS   *******************************
 ******************************************************************************/

/***************************************************************************//**
 * Copy a string into a buffer.
 ******************************************************************************/
void sl_strcpy_s(char *dst, size_t dst_size, const char *src)
{
  size_t len_copy = 0;

  if (dst == NULL) {
    return;
  }
  if (src == NULL) {
    return;
  }
  if (dst_size == 0) {
    return;
  }
  while ((*src != '\0') && (len_copy < (dst_size - 1))) {
    *dst = *src;
    dst++;
    src++;
    len_copy++;
  }
  *dst = '\0';
}

/***************************************************************************//**
 * Append the source string to the end of destination string
 ******************************************************************************/
void sl_strcat_s(char *dst, size_t dst_size, const char *src)
{
  size_t ofs;

  if (dst == NULL) {
    return;
  }
  if (src == NULL) {
    return;
  }
  if (dst_size == 0) {
    return;
  }
  ofs = sl_strlen(dst);
  if (ofs < dst_size) {
    sl_strcpy_s(&dst[ofs], dst_size - ofs, src);
  }
}

/***************************************************************************//**
 * Get the string length
 ******************************************************************************/
size_t sl_strlen(char *str)
{
  return sl_strnlen(str, SIZE_MAX);
}

/***************************************************************************//**
 * Get the string length, limited to a given length
 ******************************************************************************/
size_t sl_strnlen(char *str, size_t max_len)
{
  size_t len = 0;

  if (str == NULL) {
    return len;
  }
  while ((*str != '\0') && (len < max_len)) {
    str++;
    len++;
  }

  return len;
}

/***************************************************************************//**
 * Check if string is empty.
 ******************************************************************************/
extern inline bool sl_str_is_empty(const char *str);

/***************************************************************************//**
 * Compare two strings, ignoring case.
 ******************************************************************************/
int sl_strcasecmp(char const *a, char const *b)
{
  int d = 0;

  if ((a == NULL) || (b == NULL)) {
    return 1;
  }
  for (;; a++, b++) {
    d = tolower((unsigned char)*a) - tolower((unsigned char)*b);
    if ((d != 0) || (!*a)) {
      break;
    }
  }
  return d;
}
