/*******************************************************************************
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Utils
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

#include <sys/stat.h>

#include "misc/utils.h"
#include "misc/logging.h"

int recursive_mkdir(const char *dir, size_t len, const mode_t mode)
{
  char *tmp = NULL;
  char *p = NULL;
  struct stat sb;
  int ret;

  tmp = (char *)zalloc(len + 1);
  FATAL_ON(tmp == NULL);

  /* copy path */
  ret = snprintf(tmp, len + 1, "%s", dir);
  FATAL_ON(ret < 0 || (size_t) ret >= (len + 1));

  /* remove trailing slash */
  if (tmp[len - 1] == '/') {
    tmp[len - 1] = '\0';
  }

  /* check if path exists and is a directory */
  if (stat(tmp, &sb) == 0) {
    if (S_ISDIR(sb.st_mode)) {
      goto return_ok;
    }
  }

  /* recursive mkdir */
  for (p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = 0;
      /* test path */
      if (stat(tmp, &sb) != 0) {
        /* path does not exist - create directory */
        if (mkdir(tmp, mode) < 0) {
          goto return_err;
        }
      } else if (!S_ISDIR(sb.st_mode)) {
        /* not a directory */
        goto return_err;
      }
      *p = '/';
    }
  }

  /* test path */
  if (stat(tmp, &sb) != 0) {
    /* path does not exist - create directory */
    if (mkdir(tmp, mode) < 0) {
      goto return_err;
    }
  } else if (!S_ISDIR(sb.st_mode)) {
    /* not a directory */
    goto return_err;
  }

  /* Fall through to return_ok */

  return_ok:
  free(tmp);
  return 0;

  return_err:
  free(tmp);
  return -1;
}
