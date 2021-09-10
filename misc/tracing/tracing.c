/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Tracing Interface
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

#define _GNU_SOURCE
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "log.h"
#include "tracing.h"
#include "config.h"

static FILE * trace_file;

static pthread_mutex_t trace_mutex;

void tracing_init(void)
{
  int ret;

  if (!config_file_tracing && !config_stdout_tracing) {
    return;
  }

  if (config_file_tracing) {
    ret = mkdir(config_traces_folder, 0700);
    FATAL_SYSCALL_ON(ret < 0 && errno != EEXIST);

    ret = access(config_traces_folder, W_OK);
    FATAL_SYSCALL_ON(ret < 0);

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char buf[100];
    snprintf(buf, sizeof(buf), "%s/trace-%d-%02d-%02d_%02d-%02d-%02d.txt", config_traces_folder, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

    trace_file = fopen(buf, "w+");
    FATAL_SYSCALL_ON(trace_file == NULL);
  }

  ret = pthread_mutex_init(&trace_mutex, NULL);
  FATAL_ON(ret != 0);
}

/* Thread safe macro */
void trace(const char* string, ...)
{
  va_list vl;
  char time_string[15];

  if (!config_file_tracing && !config_stdout_tracing) {
    return;
  }

  /* get time string */
  {
    time_t current_time;
    struct tm* tm_info;

    current_time = time(NULL);

    if (current_time != ((time_t)-1)) {
      tm_info = localtime(&current_time);
      strftime(time_string, sizeof(time_string), "%H:%M:%S", tm_info);
    } else {
      WARN("cannot retreive time");
      strncpy(time_string, "time error", sizeof(time_string));
    }
  }

  va_start(vl, string);
  {
    pthread_mutex_lock(&trace_mutex);
    {
      if (config_file_tracing) {
        fprintf(trace_file, "[%s] ", time_string);
        vfprintf(trace_file, string, vl);
      }
      if (config_stdout_tracing) {
        printf("[%s] ", time_string);
        vprintf(string, vl);
      }
    }
    pthread_mutex_unlock(&trace_mutex);
  }
  va_end(vl);
}

void trace_frame(const char* string, const void* buffer, size_t len)
{
  char time_string[10];

  if (!config_file_tracing && !config_stdout_tracing) {
    return;
  }

  /* get time string */
  {
    time_t current_time;
    struct tm* tm_info;

    current_time = time(NULL);

    if (current_time == ((time_t)-1)) {
      WARN("cannot retreive time");
      return;
    }

    tm_info = localtime(&current_time);

    strftime(time_string, sizeof(time_string), "%H:%M:%S", tm_info);
  }

  pthread_mutex_lock(&trace_mutex);
  {
    if (config_file_tracing) {
      fprintf(trace_file, "[%s] ", time_string);
      fprintf(trace_file, "%s", string);
    }
    if (config_stdout_tracing) {
      printf("[%s] ", time_string);
      printf("%s", string);
    }

    size_t i;

    for (i = 0; i < len; i++) {
      if (i > 0) {
        if (config_file_tracing) {
          fprintf(trace_file, ":");
        }
        if (config_stdout_tracing) {
          printf(":");
        }
      }

      if (config_file_tracing) {
        fprintf(trace_file, "%02X", ((uint8_t*)buffer)[i]);
      }
      if (config_stdout_tracing) {
        printf("%02X", ((uint8_t*)buffer)[i]);
      }
    }

    if (config_file_tracing) {
      fprintf(trace_file, "\n");
    }
    if (config_stdout_tracing) {
      printf("\n");
    }
  }
  pthread_mutex_unlock(&trace_mutex);
}
