/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Logging module
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

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "tracing/tracing.h"

#define OUT_FILE stderr

#ifdef EXIT_BREAKPOINT
#define EXIT_OR_BREAKPOINT() do { raise(SIGTRAP); } while (0)
#else
#define EXIT_OR_BREAKPOINT() do { exit(EXIT_FAILURE); } while (0)
#endif

#define WARN(msg, ...)                                                                                                             \
  do {                                                                                                                             \
    TRACE_ASSERT("WARNING in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__);      \
    fprintf(OUT_FILE, "WARNING in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
  } while (0)

#define WARN_ON(cond) ({                                                                                                     \
    int __ret = !!(cond);                                                                                                    \
    if (__ret) {                                                                                                             \
      TRACE_ASSERT("WARNING on '%s' in function '%s' in file %s at line #%d\n", #cond, __func__, __FILE__, __LINE__);        \
      fprintf(OUT_FILE, "WARNING on '%s' in function '%s' in file %s at line #%d\n", #cond, __func__, __FILE__, __LINE__); } \
    __ret;                                                                                                                   \
  })

#define FATAL(msg, ...)                                                                                                          \
  do {                                                                                                                           \
    TRACE_ASSERT("FATAL in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__);      \
    fprintf(OUT_FILE, "FATAL in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
    EXIT_OR_BREAKPOINT();                                                                                                        \
  } while (0)

#define FATAL_ON(cond)                                                                                                   \
  do {                                                                                                                   \
    if (cond) {                                                                                                          \
      TRACE_ASSERT("FATAL on '%s' in function '%s' in file %s  at line #%d\n",#cond, __func__, __FILE__, __LINE__);      \
      fprintf(OUT_FILE, "FATAL on '%s' in function '%s' in file %s  at line #%d\n",#cond, __func__, __FILE__, __LINE__); \
      EXIT_OR_BREAKPOINT();                                                                                              \
    }                                                                                                                    \
  } while (0)

#define FATAL_SYSCALL_ON(cond)                                                                                             \
  do {                                                                                                                     \
    if (cond) {                                                                                                            \
      TRACE_ASSERT("FATAL system call in function '%s' in file %s at line #%d : %m\n", __func__, __FILE__, __LINE__);      \
      fprintf(OUT_FILE, "FATAL system call in function '%s' in file %s at line #%d : %m\n", __func__, __FILE__, __LINE__); \
      EXIT_OR_BREAKPOINT();                                                                                                \
    }                                                                                                                      \
  } while (0)

#define BUG(msg, ...)                                                                                                          \
  do {                                                                                                                         \
    TRACE_ASSERT("BUG in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__);      \
    fprintf(OUT_FILE, "BUG in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
    EXIT_OR_BREAKPOINT();                                                                                                      \
  } while (0)

#define BUG_ON(cond)                                                                                                  \
  do {                                                                                                                \
    if (cond) {                                                                                                       \
      TRACE_ASSERT("BUG on '%s' in function '%s' in file %s at line #%d\n",#cond, __func__, __FILE__, __LINE__);      \
      fprintf(OUT_FILE, "BUG on '%s' in function '%s' in file %s at line #%d\n",#cond, __func__, __FILE__, __LINE__); \
      EXIT_OR_BREAKPOINT();                                                                                           \
    }                                                                                                                 \
  } while (0)

#endif
