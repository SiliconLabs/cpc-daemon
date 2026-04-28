/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Tracing Interface
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

#include "config.h"

#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <sys/statfs.h>
#include <sys/timerfd.h>
#include <linux/magic.h>
#include <syslog.h>

#include "cpcd/config.h"
#include "cpcd/logging.h"
#include "cpcd/utils.h"
#include "cpcd/endianness.h"

#include "server_core/epoll/epoll.h"

#ifndef UNIT_TESTING
#include "driver/driver_uart.h"
#endif

#ifdef COMPILE_LTTNG
#include <lttng/tracef.h>
#endif

#define NO_LOGGING_FATAL_ON(cond)                                                                                                \
  do {                                                                                                                           \
    if (cond) {                                                                                                                  \
      fprintf(stderr, "NO LOGGER FATAL on '%s' in function '%s' in file %s  at line #%d\n",#cond, __func__, __FILE__, __LINE__); \
      exit(EXIT_FAILURE);                                                                                                        \
    }                                                                                                                            \
  } while (0)

#define NO_LOGGING_FATAL_SYSCALL_ON(cond)                                                                                                     \
  do {                                                                                                                                        \
    if (cond) {                                                                                                                               \
      fprintf(stderr, "NO LOGGER FATAL SYSCALL on '%s' in function '%s' in file %s  at line #%d : %m\n",#cond, __func__, __FILE__, __LINE__); \
      exit(EXIT_FAILURE);                                                                                                                     \
    }                                                                                                                                         \
  } while (0)

static void write_until_success_or_error(int fd, uint8_t* buff, size_t size)
{
  ssize_t ret;
  size_t written = 0;
  size_t remaining = size;

  do {
    ret = write(fd, &buff[written], remaining);
    NO_LOGGING_FATAL_SYSCALL_ON(ret < 0);
    remaining -= (size_t) ret;
    written += (size_t) ret;
  } while (remaining != 0);
}

#define MAX_LOGGERS      3
#define LOGGING_BUF_SIZE 4096

#define ASYNC_LOGGER_PAGE_SIZE    4096
#define ASYNC_LOGGER_PAGE_COUNT   7
#define ASYNC_LOGGER_BUFFER_DEPTH (ASYNC_LOGGER_PAGE_SIZE * ASYNC_LOGGER_PAGE_COUNT)
#define ASYNC_LOGGER_TIMEOUT_MS   100
#define ASYNC_LOGGER_DONT_TRIGG_UNLESS_THIS_CHUNK_SIZE ASYNC_LOGGER_PAGE_SIZE

#define TIME_STR_LEN (27)

typedef struct log_backend {
  void (*log)(int level, struct timespec *now, const char *msg, size_t len);
  void (*init)(void);
  void (*kill)(void);
} log_backend_t;

static log_backend_t *loggers[MAX_LOGGERS];

static int stats_timer_fd;

typedef struct {
  struct log_backend backend;
  FILE               *file;
  int                fd;
  uint8_t            *buffer;
  volatile size_t    buffer_size;
  volatile size_t    buffer_head;
  volatile size_t    buffer_tail;
  volatile size_t    buffer_count;
  size_t             highwater_mark;
  size_t             lost_logs;
  pthread_t          thread;
  bool               thread_started;
  volatile bool      gracefully_exit;
  pthread_cond_t     condition;
  pthread_mutex_t    mutex;
  struct timespec    timeout;
  const char         *name;
} async_logger_t;

static epoll_private_data_t* logging_private_data;

/*****************************************************************************
 ****                      ASYNC LOGGER SHARED IMPLEMENTATION            *****
 *****************************************************************************/

static const char *cpc_log_level_to_str(int log_level)
{
  switch (log_level) {
  case CPC_TRACE_LEVEL_ERROR:
    return "ERR";
    break;
  case CPC_TRACE_LEVEL_WARN:
    return "WRN";
    break;
  case CPC_TRACE_LEVEL_DEBUG:
    return "DBG";
    break;
  case CPC_TRACE_LEVEL_FRAME:
    return "TRC";
    break;
  case CPC_TRACE_LEVEL_INFO:
  default:
    return "INF";
  }
}

static int async_logger_format_header(int level, struct timespec *now, char *slice, size_t slice_len)
{
  if (now) {
  char formatted_date[20];
  struct tm tm;
  int ret;

    ret = gmtime_r(&now->tv_sec, &tm) == NULL;
    if (ret != 0) {
      return ret;
    }

    if (slice_len < TIME_STR_LEN) {
      return -1;
    }

    // XXXX-XX-XXTXX:XX:XX + .XXXXXX + Z
    strftime(formatted_date, sizeof(formatted_date), "%FT%T", &tm);
    return snprintf(slice, slice_len, "[%s.%06luZ] %s : ",
                    formatted_date, (long)now->tv_nsec / 1000,
                    cpc_log_level_to_str(level));
  } else {
    return snprintf(slice, slice_len, "%s : ",
                    cpc_log_level_to_str(level));
  }
}

static void async_logger_init(async_logger_t* logger, int file_descriptor, const char* name)
{
  int ret;

  NO_LOGGING_FATAL_ON(logger == NULL);

  logger->fd = file_descriptor;
  logger->buffer_size = ASYNC_LOGGER_BUFFER_DEPTH;
  logger->buffer_head = 0;
  logger->buffer_tail = 0;
  logger->buffer_count = 0;
  logger->highwater_mark = 0;
  logger->lost_logs = 0;
  logger->name = name;

  ret = pthread_cond_init(&logger->condition, NULL);
  NO_LOGGING_FATAL_ON(ret != 0);

  ret = pthread_mutex_init(&logger->mutex, NULL);
  NO_LOGGING_FATAL_ON(ret != 0);

  logger->buffer = zalloc(logger->buffer_size);
  NO_LOGGING_FATAL_ON(logger->buffer == NULL);

  // Lock the buffer in RAM since it's a long buffer and we will use it often to prevent
  // page faults.
  ret = mlock(logger->buffer,
              logger->buffer_size);
  NO_LOGGING_FATAL_SYSCALL_ON(ret != 0);

  logger->timeout.tv_sec = ASYNC_LOGGER_TIMEOUT_MS / 1000;
  logger->timeout.tv_nsec = (ASYNC_LOGGER_TIMEOUT_MS % 1000) * 1000000;
}

static void async_logger_append(async_logger_t *logger, const char *data, size_t length)
{
  size_t remaining = logger->buffer_size - logger->buffer_head;

  if (remaining >= length) {
    memcpy(&logger->buffer[logger->buffer_head], data, length);
    logger->buffer_head += length;
  } else { // Split write at buffer boundary
    memcpy(&logger->buffer[logger->buffer_head], data, remaining);
    memcpy(&logger->buffer[0], (const uint8_t *)data + remaining, length - remaining);
    logger->buffer_head = length - remaining;
  }

  logger->buffer_count += length;

  // Register the high water mark
  if (logger->buffer_count > logger->highwater_mark) {
    logger->highwater_mark = logger->buffer_count;
  }
}

static void async_logger_write(async_logger_t* logger, int level, struct timespec *t, const char *data, size_t length)
{
  char header[40];
  bool do_signal = false;
  size_t count_cpy;
  int header_length;

  // header array should always be big enough to contain the formatted header
  header_length = async_logger_format_header(level, t, header, sizeof(header));
  NO_LOGGING_FATAL_ON(header_length < 0 || (size_t)header_length >= sizeof(header));

  pthread_mutex_lock(&logger->mutex);
  {
    count_cpy = (size_t)header_length + length;

    if (logger->buffer_size - logger->buffer_count < count_cpy) {
      // Overflowing traces are discarded
      fprintf(stderr, "WARNING : %s logger buffer full, lost log.\n", logger->name);
      logger->lost_logs++;
    } else {
      async_logger_append(logger, header, (size_t)header_length);
      async_logger_append(logger, data, length);

      do_signal = true;
      count_cpy = logger->buffer_count;
    }
  }
  pthread_mutex_unlock(&logger->mutex);

  if (do_signal == true) {
    // Don't wake up the logger thread until sufficient data is present.
    // It will wake up at regular interval anyway to keep stdout traces (in a
    // terminal for example) fluid.
    if (count_cpy >= ASYNC_LOGGER_DONT_TRIGG_UNLESS_THIS_CHUNK_SIZE) {
      pthread_cond_signal(&logger->condition);
    }
  }
}

static void* async_logger_thread_func(void* param)
{
  async_logger_t* logger = (async_logger_t*) param;
  size_t chunk_size;
  ssize_t ret;

  while (1) {
    // Lock the mutex because we need to condition wait on the predicate 'buffer_count'
    // which is altered by both the producers and this consumer
    pthread_mutex_lock(&logger->mutex);
    {
      // Wait until there is at least the preferred no-wake-up-until data amount, a timeout or
      // a graceful exit request has been sent to us.
      while (logger->buffer_count < ASYNC_LOGGER_DONT_TRIGG_UNLESS_THIS_CHUNK_SIZE && logger->gracefully_exit == false) {
        struct timespec max_wait;

        clock_gettime(CLOCK_REALTIME, &max_wait);

        max_wait.tv_sec++;

        ret = pthread_cond_timedwait(&logger->condition,
                                     &logger->mutex,
                                     &max_wait);
        NO_LOGGING_FATAL_ON(ret != 0 && ret != ETIMEDOUT);

        if (ret == ETIMEDOUT) {
          // We have timed out or a graceful exit is pending, don't block on the condition again
          // and start writing the data we have to far.
          break;
        }
      }

      // We will write as much data as we have on hand
      chunk_size = logger->buffer_count;
    } // Unlock the mutex to allow other threads to continue to write data.
    pthread_mutex_unlock(&logger->mutex);

    if (chunk_size == 0) {
      if (logger->gracefully_exit == true) {
        // Graceful exit requested and no data, kill this thread right away.
        char buf[256];
        ret = snprintf(buf,
                       sizeof(buf),
                       "Logger buffer size = %zu, highwater mark = %zu : %.2f%%. Lost logs : %zu\n",
                       logger->buffer_size,
                       logger->highwater_mark,
                       100.0f * ((float) logger->highwater_mark / (float) logger->buffer_size),
                       logger->lost_logs);
        ret = write(logger->fd, buf, (size_t)ret);
        // Dont check for 'ret' overflow, we know 256 bytes was sufficient.
        (void)ret;
        fsync(logger->fd);
        if (logger->fd != STDOUT_FILENO) {
          ret = fclose(logger->file);
          NO_LOGGING_FATAL_ON(ret != 0);
        }
        free(logger->buffer);
        pthread_exit(NULL);
      } else {
        // We have timed out, and there's not even a single byte of logging data available.
        // Skip the rest and go back to waiting for data.
        continue;
      }
    }

    // Remaining bytes between the tail and end end of the circular buffer
    size_t remaining = logger->buffer_size - logger->buffer_tail;

    // This consumer thread is the only one manipulating the tail, so we can safely use it while the
    // lock is not held to write a chunk of data to the file. We can safely write this chunk and take
    // the time we want outside of the lock because as far as the producers are concerned,
    // this chunk is still in the buffer and cannot be overridden.
    {
      if (remaining >= chunk_size) {
        write_until_success_or_error(logger->fd,
                                     &logger->buffer[logger->buffer_tail],
                                     chunk_size);
      } else { // Split write at the buffer boundary
        write_until_success_or_error(logger->fd,
                                     &logger->buffer[logger->buffer_tail],
                                     remaining);

        write_until_success_or_error(logger->fd,
                                     &logger->buffer[0],
                                     chunk_size - remaining);
      }
    }

    // Now that the chunk is written, take back the lock to update the tail and decrease the
    // count, which is the shared variable.
    pthread_mutex_lock(&logger->mutex);
    {
      if (remaining >= chunk_size) {
        logger->buffer_tail += chunk_size;
      } else {
        logger->buffer_tail = chunk_size - remaining;
      }

      logger->buffer_count -= chunk_size;
    }
    pthread_mutex_unlock(&logger->mutex);
  }

  return NULL;
}

static void async_logger_kill(async_logger_t *logger)
{
  logger->gracefully_exit = true;

  if (logger->thread_started) {
    pthread_cond_signal(&logger->condition);
    pthread_join(logger->thread, NULL);
    logger->thread_started = false;
  }
}

/*****************************************************************************
 ****                             STDOUT (using async logger)            *****
 *****************************************************************************/

static void stdout_logging_init(void);
static void stdout_logging_kill(void);
static void stdout_log(int level, struct timespec *t, const char *data, size_t length);

static async_logger_t stdout_logger = {
  .backend = {
    .log = stdout_log,
    .init = stdout_logging_init,
    .kill = stdout_logging_kill,
  },
};

static void stdout_logging_init(void)
{
  int ret;

  async_logger_init(&stdout_logger, STDOUT_FILENO, "stdout");

  ret = pthread_create(&stdout_logger.thread,
                       NULL,
                       async_logger_thread_func,
                       &stdout_logger);
  NO_LOGGING_FATAL_ON(ret != 0);
  stdout_logger.thread_started = true;

  pthread_setname_np(stdout_logger.thread, "stdout_logger");
}

static void stdout_logging_kill(void)
{
  async_logger_kill(&stdout_logger);
}

static void stdout_log(int level, struct timespec *t, const char *data, size_t length)
{
  async_logger_write(&stdout_logger, level, t, data, length);
}

/*****************************************************************************
 ****                        FILE LOGGER (using async logger)            *****
 *****************************************************************************/

static void file_logging_init(void);
static void file_logging_kill(void);
static void file_log(int level, struct timespec *t, const char *data, size_t length);

static async_logger_t file_logger = {
  .backend = {
    .log = file_log,
    .init = file_logging_init,
    .kill = file_logging_kill,
  }
};

static void file_logging_init(void)
{
  struct statfs statfs_buf;
  int ret;

  // No file descriptor for the moment
  async_logger_init(&file_logger, -1,  "file");

  ret = recursive_mkdir(config.traces_folder, strlen(config.traces_folder), S_IRWXU | S_IRWXG | S_ISVTX);
  NO_LOGGING_FATAL_SYSCALL_ON(ret < 0);

  ret = statfs(config.traces_folder, &statfs_buf);
  NO_LOGGING_FATAL_SYSCALL_ON(ret < 0);
  if (statfs_buf.f_type != TMPFS_MAGIC) {
    WARN("Traces folder %s is not mounted on a tmpfs", config.traces_folder);
  }

  ret = access(config.traces_folder, W_OK);
  NO_LOGGING_FATAL_SYSCALL_ON(ret < 0);

  // Build file string and open file
  {
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char buf[512];
    int nchars;

    nchars = snprintf(buf,
                      sizeof(buf),
                      "%s/trace-%d-%02d-%02d_%02d-%02d-%02d.log",
                      config.traces_folder,
                      tm.tm_year + 1900,
                      tm.tm_mon + 1,
                      tm.tm_mday,
                      tm.tm_hour,
                      tm.tm_min,
                      tm.tm_sec);

    // Make sure the path fitted entirely in the struct's static buffer
    NO_LOGGING_FATAL_SYSCALL_ON(nchars < 0 || (size_t) nchars >= sizeof(buf));

    file_logger.file = fopen(buf, "w+");
    NO_LOGGING_FATAL_SYSCALL_ON(file_logger.file == NULL);

    PRINT_INFO("Logging to file enabled in file %s.", buf);
  }

  file_logger.fd = fileno(file_logger.file);

  ret = pthread_create(&file_logger.thread,
                       NULL,
                       async_logger_thread_func,
                       &file_logger);
  NO_LOGGING_FATAL_ON(ret != 0);
  file_logger.thread_started = true;

  pthread_setname_np(file_logger.thread, "file_logger");
}

static void file_logging_kill(void)
{
  async_logger_kill(&file_logger);
}

static void file_log(int level, struct timespec *t, const char *data, size_t length)
{
  async_logger_write(&file_logger, level, t, data, length);
}

/*****************************************************************************
 ****                             SYSLOG LOGGER                          *****
 *****************************************************************************/

static void syslog_logging_init(void);
static void syslog_logging_kill(void);
static void syslog_log(int level, struct timespec *t, const char *data, size_t length);

static log_backend_t syslog_logger = {
  .log = syslog_log,
  .init = syslog_logging_init,
  .kill = syslog_logging_kill,
};

static void syslog_logging_init(void)
{
  openlog("cpcd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

static void syslog_logging_kill(void)
{
  closelog();
}

static int cpc_to_syslog_prio(int level) {
  switch (level) {
    case CPC_TRACE_LEVEL_ERROR:
      return LOG_ERR;
    case CPC_TRACE_LEVEL_WARN:
      return LOG_WARNING;
    case CPC_TRACE_LEVEL_INFO:
      return LOG_INFO;
    case CPC_TRACE_LEVEL_DEBUG:
    case CPC_TRACE_LEVEL_FRAME:
      return LOG_DEBUG;
    default:
      return LOG_INFO;
  }
}

static void syslog_log(int level, struct timespec *t, const char *data, size_t length)
{
  (void)t;

  // syslog records shouldn't carry trailing newlines
  while (length && (data[length - 1] == '\n'
                 || data[length - 1] == '\r'))
    length--;

  syslog(cpc_to_syslog_prio(level), "%.*s", (int)length, data);
}

/*****************************************************************************
 ****                      STATISTICS REPORTING                          *****
 *****************************************************************************/
static void logging_print_stats(epoll_private_data_t *event_private_data)
{
  int fd_timer = event_private_data->file_descriptor;

  // Ack the timer
  {
    uint64_t expiration;
    ssize_t ret;

    ret = read(fd_timer, &expiration, sizeof(expiration));
    FATAL_ON(ret < 0);
  }

  TRACE_DEBUG("Host core debug counters:"
              "\nendpoint_opened %u"
              "\nendpoint_closed %u"
              "\nrxd_frame %u"
              "\nrxd_valid_iframe %u"
              "\nrxd_valid_uframe %u"
              "\nrxd_valid_sframe %u"
              "\nrxd_data_frame_dropped %u"
              "\ntxd_reject_destination_unreachable %u"
              "\ntxd_reject_error_fault %u"
              "\ntxd_completed %u"
              "\nretxd_data_frame %u"
              "\ndriver_packet_dropped %u"
              "\ninvalid_header_checksum %u"
              "\ninvalid_payload_checksum %u\n",
              primary_core_debug_counters.endpoint_opened,
              primary_core_debug_counters.endpoint_closed,
              primary_core_debug_counters.rxd_frame,
              primary_core_debug_counters.rxd_valid_iframe,
              primary_core_debug_counters.rxd_valid_uframe,
              primary_core_debug_counters.rxd_valid_sframe,
              primary_core_debug_counters.rxd_data_frame_dropped,
              primary_core_debug_counters.txd_reject_destination_unreachable,
              primary_core_debug_counters.txd_reject_error_fault,
              primary_core_debug_counters.txd_completed,
              primary_core_debug_counters.retxd_data_frame,
              primary_core_debug_counters.driver_packet_dropped,
              primary_core_debug_counters.invalid_header_checksum,
              primary_core_debug_counters.invalid_payload_checksum);

  TRACE_DEBUG("RCP core debug counters"
              "\nendpoint_opened %u"
              "\nendpoint_closed %u"
              "\nrxd_frame %u"
              "\nrxd_valid_iframe %u"
              "\nrxd_valid_uframe %u"
              "\nrxd_valid_sframe %u"
              "\nrxd_data_frame_dropped %u"
              "\ntxd_reject_destination_unreachable %u"
              "\ntxd_reject_error_fault %u"
              "\ntxd_completed %u"
              "\nretxd_data_frame %u"
              "\ndriver_error %u"
              "\ndriver_packet_dropped %u"
              "\ninvalid_header_checksum %u"
              "\ninvalid_payload_checksum %u\n",
              secondary_core_debug_counters.endpoint_opened,
              secondary_core_debug_counters.endpoint_closed,
              secondary_core_debug_counters.rxd_frame,
              secondary_core_debug_counters.rxd_valid_iframe,
              secondary_core_debug_counters.rxd_valid_uframe,
              secondary_core_debug_counters.rxd_valid_sframe,
              secondary_core_debug_counters.rxd_data_frame_dropped,
              secondary_core_debug_counters.txd_reject_destination_unreachable,
              secondary_core_debug_counters.txd_reject_error_fault,
              secondary_core_debug_counters.txd_completed,
              secondary_core_debug_counters.retxd_data_frame,
              secondary_core_debug_counters.driver_error,
              secondary_core_debug_counters.driver_packet_dropped,
              secondary_core_debug_counters.invalid_header_checksum,
              secondary_core_debug_counters.invalid_payload_checksum);

#ifndef UNIT_TESTING
  if (config.bus == UART) {
    driver_uart_print_overruns();
  }
#endif
}

void logging_init_stats(void)
{
  // Setup timer
  stats_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
  FATAL_SYSCALL_ON(stats_timer_fd < 0);

  struct itimerspec timeout_time = { .it_interval = { .tv_sec = config.stats_interval, .tv_nsec = 0 },
                                     .it_value    = { .tv_sec = config.stats_interval, .tv_nsec = 0 } };

  int ret = timerfd_settime(stats_timer_fd,
                            0,
                            &timeout_time,
                            NULL);

  FATAL_SYSCALL_ON(ret < 0);

  // Setup epoll
  {
    logging_private_data = (epoll_private_data_t*) zalloc(sizeof(epoll_private_data_t));
    FATAL_ON(logging_private_data == NULL);

    logging_private_data->callback = logging_print_stats;
    logging_private_data->file_descriptor = stats_timer_fd;

    epoll_register(logging_private_data);
  }
}

static void log_to_backends(int level, bool include_timestamp, char *str, size_t len)
{
  struct timespec *p_now = NULL;
  struct timespec now;
  int ret;

  if (include_timestamp) {
    ret = clock_gettime(CLOCK_REALTIME, &now);
    if (ret < 0) {
      return;
    }

    p_now = &now;
  }

  for (int i = 0; i < MAX_LOGGERS; i++) {
    if (loggers[i] != NULL)
      loggers[i]->log(level, p_now, str, len);
  }
}

void trace(int level, bool include_timestamp, const char* string, ...)
{
  char log_string[LOGGING_BUF_SIZE];
  size_t total_length = 0;
  int errno_backup = errno;

  // Append formatted text
  {
    va_list vl;
    int ret;

    va_start(vl, string);
    {
      ret = vsnprintf(log_string, sizeof(log_string), string, vl);

      NO_LOGGING_FATAL_ON(ret < 0);

      total_length = (size_t)ret;
      if (total_length >= sizeof(log_string)) {
        fprintf(stderr, "Truncated log message\n");
        // The string was truncated, terminate it properly
        log_string[sizeof(log_string) - 1] = '\n';
        total_length = sizeof(log_string);
      }
    }
    va_end(vl);
  }

  log_to_backends(level, include_timestamp, log_string, total_length);

  errno = errno_backup;
}

static inline void byte_to_hex(uint8_t byte, char str[2])
{
  static const char HEX[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
  str[0] = HEX[byte >> 4];
  str[1] = HEX[byte & 0x0F];
}

void trace_frame(const char* string, const void* buffer, size_t len)
{
  char log_string[LOGGING_BUF_SIZE];
  size_t log_string_length = 0;
  uint8_t* frame = (uint8_t*) buffer;
  int errno_backup = errno;
  bool include_timestamp = true;

  // Append string up to buffer
  for (size_t i = 0; string[i] != '\0'; i++) {
    // Edge case where the string itself can fill the whole buffer..
    if (log_string_length >= sizeof(log_string)) {

      log_to_backends(CPC_TRACE_LEVEL_FRAME, include_timestamp, log_string, log_string_length);

      // Start at the beginning
      log_string_length = 0;
      include_timestamp = false;
    }

    log_string[log_string_length++] = string[i];
  }

  // Append hex data
  for (size_t i = 0; i != len; i++) {
    // In the case of large buffer, its possible we reach the end of the buffer
    // in the middle of the parsing, flush the buffer
    if (log_string_length >= sizeof(log_string) - sizeof("xx:")) {
      // Flush the buffer
      log_to_backends(CPC_TRACE_LEVEL_FRAME, include_timestamp, log_string, log_string_length);

      // Start at the beginning
      log_string_length = 0;
      include_timestamp = false;
    }

    byte_to_hex(frame[i], log_string + log_string_length);
    log_string_length += 2;

    log_string[log_string_length++] = ':';
  }

  // Newline terminate the string (overriding the last semicolon)
  if (log_string_length) {
    log_string[log_string_length - 1] = '\n';

    log_to_backends(CPC_TRACE_LEVEL_FRAME, include_timestamp, log_string, log_string_length);
  }

  errno = errno_backup;
}

static void enable_logger(log_backend_t *logger)
{
  bool enabled = false;

  for (int i = 0; i < MAX_LOGGERS; i++) {
    if (loggers[i] == NULL) {
      logger->init();
      loggers[i] = logger;
      enabled = true;

      break;
    }
  }

  NO_LOGGING_FATAL_ON(!enabled);
}

void logging_init_stdout(void)
{
  enable_logger(&stdout_logger.backend);
}

void logging_init_file(void)
{
  enable_logger(&file_logger.backend);
}

void logging_init_syslog(void)
{
  enable_logger(&syslog_logger);
}

void logging_kill(void)
{
  // Note we don't cancel the threads, we let them finish
  for (int i = MAX_LOGGERS - 1; i >= 0; i--) {
    log_backend_t *logger = loggers[i];
    if (logger) {
      loggers[i] = NULL;
      logger->kill();
    }
  }

  free(logging_private_data);
}
