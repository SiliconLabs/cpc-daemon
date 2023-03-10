/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) - Library Implementation
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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "sl_cpc.h"
#include "version.h"
#include "misc/utils.h"
#include "misc/sleep.h"
#include "server_core/cpcd_exchange.h"
#include "server_core/cpcd_event.h"

#ifdef COMPILE_LTTNG
#include <lttng/tracef.h>
#define LTTNG_TRACE(string, ...)  tracef(string, ##__VA_ARGS__)
#else
#define LTTNG_TRACE(string, ...) (void)0
#endif

typedef struct {
  int ctrl_sock_fd;
  pthread_mutex_t ctrl_sock_fd_lock;
  size_t max_write_size;
  char *secondary_app_version;
  bool enable_tracing;
  char* instance_name;
  bool initialized;
} sli_cpc_handle_t;

typedef struct {
  uint8_t id;
  int server_sock_fd;
  int sock_fd;
  pthread_mutex_t sock_fd_lock;
  sli_cpc_handle_t *lib_handle;
} sli_cpc_endpoint_t;

typedef struct {
  int endpoint_id;
  int sock_fd;
  pthread_mutex_t sock_fd_lock;
  sli_cpc_handle_t *lib_handle;
} sli_cpc_endpoint_event_handle_t;

static void lib_trace(sli_cpc_handle_t* lib_handle, FILE *__restrict __stream, const char* string, ...)
{
  char time_string[25];
  int errno_backup;

  // backup current errno as syscalls below might override it
  errno_backup = errno;

  /* get time string */
  {
    long us;
    time_t s;
    struct timespec spec;
    struct tm* tm_info;

    int ret = clock_gettime(CLOCK_REALTIME, &spec);

    s = spec.tv_sec;

    us = spec.tv_nsec / 1000;
    if (us > 999999) {
      s++;
      us = 0;
    }

    if (ret != -1) {
      tm_info = localtime(&s);
      size_t r = strftime(time_string, sizeof(time_string), "%H:%M:%S", tm_info);
      sprintf(&time_string[r], ":%06ld", us);
    } else {
      strncpy(time_string, "time error", sizeof(time_string));
    }
  }

  fprintf(__stream, "[%s] libcpc(%s) ", time_string, lib_handle->instance_name);

  va_list vl;

  va_start(vl, string);
  {
    errno = errno_backup;
    vfprintf(__stream, string, vl);
    fflush(__stream);
  }
  va_end(vl);

  errno = errno_backup;
}

#define TRACE_LIB(lib_handle, format, args ...)     \
  do {                                              \
    if (lib_handle->enable_tracing) {               \
      lib_trace(lib_handle,                         \
                stderr,                             \
                "[%s:%d]: " format "\n",            \
                __FUNCTION__, __LINE__, ## args);   \
      LTTNG_TRACE("libcpc: " format "\n", ## args); \
    }                                               \
  } while (0)

// trace an error, "error" is expected to be a negative value of errno,
// eg. -EINVAL or -ENOMEM
#define TRACE_LIB_ERROR(lib_handle, error, format, args ...)        \
  do {                                                              \
    if (lib_handle->enable_tracing) {                               \
      lib_trace(lib_handle,                                         \
                stderr,                                             \
                "[%s:%d]: " format " : errno %s\n",                 \
                __FUNCTION__, __LINE__, ## args, strerror(-error)); \
      LTTNG_TRACE("libcpc: " format "\n", ## args);                 \
    }                                                               \
  } while (0)

// trace an error with the current errno (useful after a failed syscall)
#define TRACE_LIB_ERRNO(lib_handle, format, args ...) \
  TRACE_LIB_ERROR(lib_handle, -errno, format, ## args)

#define INIT_CPC_RET(type) type __cpc_ret = 0
#define RETURN_CPC_RET return __cpc_ret
#define SET_CPC_RET(error) \
  do {                     \
    if (__cpc_ret == 0) {  \
      __cpc_ret = error;   \
    }                      \
  } while (0)

#ifndef DEFAULT_INSTANCE_NAME
  #define DEFAULT_INSTANCE_NAME "cpcd_0"
#endif

#define CTRL_SOCKET_TIMEOUT_SEC 2

#define DEFAULT_ENDPOINT_SOCKET_SIZE SL_CPC_READ_MINIMUM_SIZE

static cpc_reset_callback_t saved_reset_callback;

int cpc_deinit(cpc_handle_t *handle);

static int cpc_query_exchange(sli_cpc_handle_t *lib_handle, int fd, cpcd_exchange_type_t type, uint8_t ep_id,
                              void *payload, size_t payload_sz)
{
  INIT_CPC_RET(int);
  cpcd_exchange_buffer_t *query = NULL;
  ssize_t bytes_written = 0;
  ssize_t bytes_read = 0;
  const size_t query_len = sizeof(cpcd_exchange_buffer_t) + payload_sz;

  query = zalloc(query_len);
  if (query == NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%d) failed", query_len);
    SET_CPC_RET(-ENOMEM);
    RETURN_CPC_RET;
  }

  query->type = type;
  query->endpoint_number = ep_id;
  if (payload_sz) {
    memcpy(query->payload, payload, payload_sz);
  }

  bytes_written = send(fd, query, query_len, 0);
  if (bytes_written < (ssize_t)query_len) {
    if (bytes_written == -1) {
      TRACE_LIB_ERRNO(lib_handle, "send(%d) failed", fd);
      SET_CPC_RET(-errno);
    } else {
      TRACE_LIB_ERROR(lib_handle, -EBADE, "send(%d) failed, ret = %d", fd, bytes_written);
      SET_CPC_RET(-EBADE);
    }
    goto free_query;
  }

  bytes_read = recv(fd, query, query_len, 0);
  if (bytes_read != (ssize_t)query_len) {
    if (bytes_read == 0) {
      TRACE_LIB_ERROR(lib_handle, -ECONNRESET, "recv(%d) failed", fd);
      SET_CPC_RET(-ECONNRESET);
    } else if (bytes_read == -1) {
      TRACE_LIB_ERRNO(lib_handle, "recv(%d) failed", fd);
      SET_CPC_RET(-errno);
    } else {
      TRACE_LIB_ERROR(lib_handle, -EBADE, "recv(%d) failed, ret = %d", fd, bytes_read);
      SET_CPC_RET(-EBADE);
    }
    goto free_query;
  }

  if (payload_sz) {
    memcpy(payload, query->payload, payload_sz);
  }

  free_query:
  free(query);

  RETURN_CPC_RET;
}

static int cpc_query_receive(sli_cpc_handle_t *lib_handle, int fd, void *payload, size_t payload_sz)
{
  INIT_CPC_RET(int);
  cpcd_exchange_buffer_t *query = NULL;
  ssize_t bytes_read = 0;
  const size_t query_len = sizeof(cpcd_exchange_buffer_t) + payload_sz;

  query = zalloc(query_len);
  if (query == NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%d) failed", query_len);
    SET_CPC_RET(-ENOMEM);
    RETURN_CPC_RET;
  }

  bytes_read = recv(fd, query, query_len, 0);
  if (bytes_read != (ssize_t)query_len) {
    if (bytes_read == 0) {
      TRACE_LIB_ERROR(lib_handle, -ECONNRESET, "recv(%d) failed", fd);
      SET_CPC_RET(-ECONNRESET);
    } else if (bytes_read == -1) {
      TRACE_LIB_ERRNO(lib_handle, "recv(%d) failed", fd);
      SET_CPC_RET(-errno);
    } else {
      TRACE_LIB_ERROR(lib_handle, -EBADE, "recv(%d) failed, ret = %d", fd, bytes_read);
      SET_CPC_RET(-EBADE);
    }

    goto free_query;
  }

  if (payload_sz && payload) {
    memcpy(payload, query->payload, payload_sz);
  }

  free_query:
  free(query);

  RETURN_CPC_RET;
}

static int get_max_write(sli_cpc_handle_t *lib_handle)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  uint32_t max_write_size = 0;

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_MAX_WRITE_SIZE_QUERY, 0,
                               (void*)&max_write_size, sizeof(max_write_size));

  if (tmp_ret == 0) {
    lib_handle->max_write_size = (size_t)max_write_size;
  } else {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to exchange max write size query");
    SET_CPC_RET(tmp_ret);
  }

  RETURN_CPC_RET;
}

static int check_version(sli_cpc_handle_t *lib_handle)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  char version[PROJECT_MAX_VERSION_SIZE];

  strncpy(version, PROJECT_VER, PROJECT_MAX_VERSION_SIZE);

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_VERSION_QUERY, 0,
                               (void*)version, PROJECT_MAX_VERSION_SIZE);

  if (tmp_ret) {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to exchange version query");
    SET_CPC_RET(tmp_ret);
    RETURN_CPC_RET;
  }

  if (strncmp(version, PROJECT_VER, PROJECT_MAX_VERSION_SIZE) != 0) {
    TRACE_LIB_ERROR(lib_handle, -ELIBBAD, "libcpc version does not match with the daemon");
    SET_CPC_RET(-ELIBBAD);
    RETURN_CPC_RET;
  }

  RETURN_CPC_RET;
}

static int check_normal_operation_mode(sli_cpc_handle_t *lib_handle)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  bool normal_operation_mode = false;

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_NORMAL_OPERATION_MODE_QUERY, 0,
                               (void*)&normal_operation_mode, sizeof(bool));

  if (tmp_ret) {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to exchange normal operation mode query");
    SET_CPC_RET(tmp_ret);
    RETURN_CPC_RET;
  }

  if (!normal_operation_mode) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "daemon is not running in normal operation mode");
    SET_CPC_RET(-EPERM);
    RETURN_CPC_RET;
  }

  RETURN_CPC_RET;
}

static int get_secondary_app_version(sli_cpc_handle_t *lib_handle)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  uint16_t app_string_size = 0;

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_SECONDARY_APP_VERSION_SIZE_QUERY, 0,
                               (void*)&app_string_size, sizeof(app_string_size));
  if (tmp_ret) {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to exchange secondary app version size query");
    SET_CPC_RET(tmp_ret);
    RETURN_CPC_RET;
  }

  lib_handle->secondary_app_version = zalloc((size_t)app_string_size + 1);
  if (lib_handle->secondary_app_version == NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%d) failed", (size_t)app_string_size + 1);
    SET_CPC_RET(-ENOMEM);
    RETURN_CPC_RET;
  }

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_SECONDARY_APP_VERSION_STRING_QUERY, 0,
                               (void*)lib_handle->secondary_app_version, app_string_size);

  if (tmp_ret) {
    free(lib_handle->secondary_app_version);
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to exchange secondary app version string query");
    SET_CPC_RET(tmp_ret);
    RETURN_CPC_RET;
  }

  lib_handle->secondary_app_version[app_string_size] = '\0';
  TRACE_LIB(lib_handle, "secondary application is v%s", lib_handle->secondary_app_version);

  RETURN_CPC_RET;
}

static int set_pid(sli_cpc_handle_t *lib_handle)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  bool can_connect = false;
  ssize_t bytes_written = 0;
  const pid_t pid = getpid();
  const size_t set_pid_query_len = sizeof(cpcd_exchange_buffer_t) + sizeof(pid_t);
  uint8_t buf[set_pid_query_len];
  cpcd_exchange_buffer_t* set_pid_query = (cpcd_exchange_buffer_t*)buf;

  set_pid_query->type = EXCHANGE_SET_PID_QUERY;
  set_pid_query->endpoint_number = 0;

  memcpy(set_pid_query->payload, &pid, sizeof(pid_t));

  bytes_written = send(lib_handle->ctrl_sock_fd, set_pid_query, set_pid_query_len, 0);
  if (bytes_written < (ssize_t)set_pid_query_len) {
    TRACE_LIB_ERRNO(lib_handle, "send(%d) failed", lib_handle->ctrl_sock_fd);
    SET_CPC_RET(-errno);
    RETURN_CPC_RET;
  }

  tmp_ret = cpc_query_receive(lib_handle, lib_handle->ctrl_sock_fd, &can_connect, sizeof(bool));
  if (tmp_ret == 0) {
    if (can_connect) {
      TRACE_LIB(lib_handle, "pid %d registered with daemon", pid);
    } else {
      TRACE_LIB_ERROR(lib_handle, -ELIBMAX, "cannot set pid %d, another process with same pid is already registered", pid);
      SET_CPC_RET(-ELIBMAX);
      RETURN_CPC_RET;
    }
  } else {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to exchange set pid query");
    SET_CPC_RET(tmp_ret);
    RETURN_CPC_RET;
  }

  RETURN_CPC_RET;
}

static int get_endpoint_encryption(sli_cpc_endpoint_t *ep, bool *encryption)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  sli_cpc_handle_t *lib_handle = ep->lib_handle;

  tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_lock(%p) failed", &lib_handle->ctrl_sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
    RETURN_CPC_RET;
  }

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_ENDPOINT_ENCRYPTION_QUERY, ep->id,
                               (void*)encryption, sizeof(bool));

  if (tmp_ret) {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to exchange endpoint encryption query");
    SET_CPC_RET(tmp_ret);
  }

  tmp_ret = pthread_mutex_unlock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed", &lib_handle->ctrl_sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
    RETURN_CPC_RET;
  }

  RETURN_CPC_RET;
}

static void SIGUSR1_handler(int signum)
{
  (void) signum;

  if (saved_reset_callback != NULL) {
    saved_reset_callback();
  }
}

/***************************************************************************//**
 * Initialize the CPC library.
 * Upon success, users will get a handle that must be passed to subsequent calls.
 ******************************************************************************/
int cpc_init(cpc_handle_t *handle, const char *instance_name, bool enable_tracing, cpc_reset_callback_t reset_callback)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  sli_cpc_handle_t *lib_handle = NULL;
  struct sockaddr_un server_addr = { 0 };

  if (handle == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lib_handle = zalloc(sizeof(sli_cpc_handle_t));
  if (lib_handle == NULL) {
    SET_CPC_RET(-ENOMEM);
    RETURN_CPC_RET;
  }

  /* Save the parameters internally for possible further re-init */
  lib_handle->enable_tracing = enable_tracing;
  saved_reset_callback = reset_callback;

  if (instance_name == NULL) {
    /* If the instance name is NULL, use the default name */
    lib_handle->instance_name = strdup(DEFAULT_INSTANCE_NAME);
    if (lib_handle->instance_name == NULL) {
      SET_CPC_RET(-errno);
      goto free_lib_handle;
    }
  } else {
    /* Instead, use the one supplied by the user */
    lib_handle->instance_name = strdup(instance_name);
    if (lib_handle->instance_name == NULL) {
      SET_CPC_RET(-errno);
      goto free_lib_handle;
    }
  }

  /* Create the control socket path */
  {
    int nchars;
    const size_t size = sizeof(server_addr.sun_path) - 1;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;

    nchars = snprintf(server_addr.sun_path, size, "%s/cpcd/%s/ctrl.cpcd.sock", CPC_SOCKET_DIR, lib_handle->instance_name);

    /* Make sure the path fitted entirely in the struct's static buffer */
    if (nchars < 0 || (size_t) nchars >= size) {
      TRACE_LIB_ERROR(lib_handle, -ERANGE, "socket path '%s/cpcd/%s/ctrl.cpcd.sock' does not fit in buffer", CPC_SOCKET_DIR, lib_handle->instance_name);
      SET_CPC_RET(-ERANGE);
      goto free_instance_name;
    }
  }

  // Check if control socket exists
  if (access(server_addr.sun_path, F_OK) != 0) {
    TRACE_LIB_ERRNO(lib_handle,
                    "access() : %s doesn't exist. The daemon is not started or "
                    "the reset sequence is not done or the secondary is not responsive.",
                    server_addr.sun_path);
    SET_CPC_RET(-errno);
    goto free_instance_name;
  }

  lib_handle->ctrl_sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (lib_handle->ctrl_sock_fd < 0) {
    TRACE_LIB_ERRNO(lib_handle, "socket() failed");
    SET_CPC_RET(-errno);
    goto free_instance_name;
  }

  if (connect(lib_handle->ctrl_sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
    TRACE_LIB_ERRNO(lib_handle,
                    "connect() : could not connect to %s. Either the process does not have "
                    "the correct permissions or the secondary is not responsive.",
                    server_addr.sun_path);
    SET_CPC_RET(-errno);
    goto close_ctrl_sock_fd;
  }

  // Set ctrl socket timeout
  struct timeval timeout;
  timeout.tv_sec = CTRL_SOCKET_TIMEOUT_SEC;
  timeout.tv_usec = 0;

  if (setsockopt(lib_handle->ctrl_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "setsockopt(%d) failed", lib_handle->ctrl_sock_fd);
    SET_CPC_RET(-errno);
    goto close_ctrl_sock_fd;
  }

  tmp_ret = check_version(lib_handle);
  if (tmp_ret < 0) {
    SET_CPC_RET(tmp_ret);
    goto close_ctrl_sock_fd;
  }

  tmp_ret = set_pid(lib_handle);
  if (tmp_ret < 0) {
    SET_CPC_RET(tmp_ret);
    goto close_ctrl_sock_fd;
  }

  tmp_ret = check_normal_operation_mode(lib_handle);
  if (tmp_ret < 0) {
    SET_CPC_RET(tmp_ret);
    goto close_ctrl_sock_fd;
  }

  // Check if reset callback is define
  if (reset_callback != NULL) {
    signal(SIGUSR1, SIGUSR1_handler);
  }

  // Check if control socket exists
  if (access(server_addr.sun_path, F_OK) != 0) {
    TRACE_LIB_ERRNO(lib_handle,
                    "access() : %s doesn't exist. The daemon is not started or the reset "
                    "sequence is not done or the secondary is not responsive.",
                    server_addr.sun_path);
    SET_CPC_RET(-errno);
    goto close_ctrl_sock_fd;
  }

  tmp_ret = get_max_write(lib_handle);
  if (tmp_ret < 0) {
    SET_CPC_RET(tmp_ret);
    goto close_ctrl_sock_fd;
  }

  tmp_ret = get_secondary_app_version(lib_handle);
  if (tmp_ret < 0) {
    SET_CPC_RET(tmp_ret);
    goto close_ctrl_sock_fd;
  }

  tmp_ret = pthread_mutex_init(&lib_handle->ctrl_sock_fd_lock, NULL);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_init(%p) failed", &lib_handle->ctrl_sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
    goto free_secondary_app_version;
  }

  lib_handle->initialized = true;
  handle->ptr = (void *)lib_handle;
  TRACE_LIB(lib_handle, "cpc lib initialized");

  RETURN_CPC_RET;

  free_secondary_app_version:
  free(lib_handle->secondary_app_version);

  close_ctrl_sock_fd:
  if (close(lib_handle->ctrl_sock_fd) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "close(%d) failed", lib_handle->ctrl_sock_fd);
    SET_CPC_RET(-errno);
  }

  free_instance_name:
  free(lib_handle->instance_name);

  free_lib_handle:
  free(lib_handle);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * De-init the library handle and any allocated resources
 ******************************************************************************/
int cpc_deinit(cpc_handle_t *handle)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  sli_cpc_handle_t *lib_handle = NULL;

  if (handle->ptr == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lib_handle = (sli_cpc_handle_t *)handle->ptr;

  if (close(lib_handle->ctrl_sock_fd) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "close(%d) failed", lib_handle->ctrl_sock_fd);
  }

  tmp_ret = pthread_mutex_destroy(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_destroy(%p) failed, free up resources anyway", &lib_handle->ctrl_sock_fd_lock);
  }

  TRACE_LIB(lib_handle, "cpc lib deinitialized");

  free(lib_handle->instance_name);
  free(lib_handle->secondary_app_version);
  free(lib_handle);

  handle->ptr = NULL;

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Restart the CPC library.
 * The user is notified via the 'reset_callback' when the secondary has restarted.
 * The user logic then has to call this function in order to [try] to re-connect
 * the application to the daemon.
 ******************************************************************************/
int cpc_restart(cpc_handle_t *handle)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  sli_cpc_handle_t *lib_handle = NULL;

  if (handle->ptr == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lib_handle = (sli_cpc_handle_t *)handle->ptr;

  sli_cpc_handle_t *lib_handle_copy = zalloc(sizeof(sli_cpc_handle_t));
  if (lib_handle_copy == NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%d) failed", sizeof(sli_cpc_handle_t));
    SET_CPC_RET(-ENOMEM);
    RETURN_CPC_RET;
  }

  memcpy(lib_handle_copy, lib_handle, sizeof(sli_cpc_handle_t));
  lib_handle_copy->instance_name = strdup(lib_handle->instance_name);
  if (lib_handle_copy->instance_name == NULL) {
    free(lib_handle_copy);
    TRACE_LIB_ERRNO(lib_handle, "failed to copy the instance name");
    SET_CPC_RET(-errno);
    RETURN_CPC_RET;
  }

  // De-init the original handle
  if (lib_handle_copy->initialized) {
    tmp_ret = cpc_deinit(handle);
    if (tmp_ret != 0) {
      // Restore the handle copy on failure
      free(lib_handle_copy->instance_name);
      lib_handle_copy->instance_name = lib_handle->instance_name;
      handle->ptr = (void *)lib_handle_copy;

      TRACE_LIB_ERROR(lib_handle, tmp_ret, "cpc_deinit(%p) failed", handle);
      SET_CPC_RET(tmp_ret);
      RETURN_CPC_RET;
    }
  }

  // De-init was successful, invalidate copy
  lib_handle_copy->initialized = false;

  // Attemps a connection
  tmp_ret = cpc_init(handle, lib_handle_copy->instance_name, lib_handle_copy->enable_tracing, saved_reset_callback);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle_copy, tmp_ret, "Failed cpc_init, attempting again in %d milliseconds", CPCD_REBOOT_TIME_MS);
    sleep_ms(CPCD_REBOOT_TIME_MS);  // Wait for the minimum time it takes for CPCd to reboot

    tmp_ret = cpc_init(handle, lib_handle_copy->instance_name, lib_handle_copy->enable_tracing, saved_reset_callback);
    if (tmp_ret != 0) {
      // Restore the handle copy on failure
      handle->ptr = (void *)lib_handle_copy;
      TRACE_LIB_ERROR(lib_handle_copy, tmp_ret, "cpc_init(%p) failed", handle);
      SET_CPC_RET(tmp_ret);
      RETURN_CPC_RET;
    }
  }

  // On success we can free the lib_handle_copy
  free(lib_handle_copy->instance_name);
  free(lib_handle_copy);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Connect to the socket corresponding to the provided endpoint ID.
 * The function will also allocate the memory for the endpoint structure and assign
 * it to the provided pointer.
 * This endpoint structure must then be used for further calls to the libcpc.
 ******************************************************************************/
int cpc_open_endpoint(cpc_handle_t handle, cpc_endpoint_t *endpoint, uint8_t id, uint8_t tx_window_size)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  int tmp_ret2 = 0;
  bool can_open = false;
  sli_cpc_handle_t *lib_handle = NULL;
  sli_cpc_endpoint_t *ep = NULL;
  struct sockaddr_un ep_addr = { 0 };

  if (id == SL_CPC_ENDPOINT_SYSTEM || endpoint == NULL || handle.ptr == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lib_handle = (sli_cpc_handle_t *)handle.ptr;

  if (tx_window_size != 1) {
    TRACE_LIB_ERROR(lib_handle, -EINVAL, "Only a tx window of 1 is supported at the moment");
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  TRACE_LIB(lib_handle, "opening EP #%d", id);

  ep_addr.sun_family = AF_UNIX;

  /* Create the endpoint socket path */
  {
    int nchars;
    const size_t size = sizeof(ep_addr.sun_path) - 1;

    nchars = snprintf(ep_addr.sun_path, size, "%s/cpcd/%s/ep%d.cpcd.sock", CPC_SOCKET_DIR, lib_handle->instance_name, id);

    /* Make sure the path fitted entirely in the struct sockaddr_un's static buffer */
    if (nchars < 0 || (size_t) nchars >= size) {
      TRACE_LIB_ERROR(lib_handle, -ERANGE, "socket path '%s/cpcd/%s/ep%d.cpcd.sock' does not fit in buffer", CPC_SOCKET_DIR, lib_handle->instance_name, id);
      SET_CPC_RET(-ERANGE);
      RETURN_CPC_RET;
    }
  }

  ep = zalloc(sizeof(sli_cpc_endpoint_t));
  if (ep == NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%d) failed", sizeof(sli_cpc_endpoint_t));
    SET_CPC_RET(-ERANGE);
    RETURN_CPC_RET;
  }

  ep->id = id;
  ep->lib_handle = lib_handle;

  tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_lock(%p) failed", &lib_handle->ctrl_sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
    goto free_endpoint;
  }

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_OPEN_ENDPOINT_QUERY, id,
                               (void*)&can_open, sizeof(can_open));

  if (tmp_ret) {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to exchange open endpoint query");
    SET_CPC_RET(tmp_ret);
  }

  tmp_ret2 = pthread_mutex_unlock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret2 != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret2, "pthread_mutex_unlock(%p) failed", &lib_handle->ctrl_sock_fd_lock);
    SET_CPC_RET(-tmp_ret2);
    goto free_endpoint;
  }

  if (tmp_ret) {
    goto free_endpoint;
  }

  if (can_open == false) {
    if (id == SL_CPC_ENDPOINT_SECURITY) {
      TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot open security endpoint as a client");
      SET_CPC_RET(-EPERM);
    } else {
      TRACE_LIB_ERROR(lib_handle, -EAGAIN, "endpoint on secondary is not opened");
      SET_CPC_RET(-EAGAIN);
    }
    goto free_endpoint;
  }

  ep->sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (ep->sock_fd < 0) {
    TRACE_LIB_ERRNO(lib_handle, "socket()");
    SET_CPC_RET(-errno);
    goto free_endpoint;
  }

  tmp_ret = connect(ep->sock_fd, (struct sockaddr *)&ep_addr, sizeof(ep_addr));
  if (tmp_ret < 0) {
    TRACE_LIB_ERRNO(lib_handle, "connect(%d) failed", ep->sock_fd);
    SET_CPC_RET(-errno);
    goto close_sock_fd;
  }

  tmp_ret = cpc_query_receive(lib_handle, ep->sock_fd, (void*)&ep->server_sock_fd, sizeof(ep->server_sock_fd));
  if (tmp_ret) {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to receive server ack");
    SET_CPC_RET(tmp_ret);
    goto close_sock_fd;
  }

  int ep_socket_size = DEFAULT_ENDPOINT_SOCKET_SIZE;
  tmp_ret = setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, &ep_socket_size, sizeof(int));
  if (tmp_ret != 0) {
    TRACE_LIB_ERRNO(lib_handle, "setsockopt(%d) failed", ep->sock_fd);
    SET_CPC_RET(-errno);
    goto close_sock_fd;
  }

  tmp_ret = pthread_mutex_init(&ep->sock_fd_lock, NULL);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_init(%p) failed", &ep->sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
    goto close_sock_fd;
  }

  TRACE_LIB(lib_handle, "opened EP #%d", ep->id);
  endpoint->ptr = (void *)ep;

  SET_CPC_RET(ep->sock_fd);
  RETURN_CPC_RET;

  close_sock_fd:
  if (close(ep->sock_fd) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "close(%d) failed", ep->sock_fd);
    SET_CPC_RET(-errno);
  }

  free_endpoint:
  free(ep);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Close the socket connection to the endpoint.
 * This function will also free the memory used to allocate the endpoint structure.
 ******************************************************************************/
int cpc_close_endpoint(cpc_endpoint_t *endpoint)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  sli_cpc_handle_t *lib_handle = NULL;
  sli_cpc_endpoint_t *ep = NULL;

  if (endpoint == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  ep = (sli_cpc_endpoint_t *)endpoint->ptr;
  if (ep == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lib_handle = ep->lib_handle;

  tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_lock(%p) failed", &lib_handle->ctrl_sock_fd_lock);
    goto destroy_mutex;
  }

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_CLOSE_ENDPOINT_QUERY, ep->id,
                               (void*)&ep->server_sock_fd, sizeof(ep->server_sock_fd));

  if (tmp_ret) {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to exchange close endpoint query");
  }

  TRACE_LIB(lib_handle, "closing EP #%d", ep->id);

  if (close(ep->sock_fd) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "close(%d) failed", ep->sock_fd);
    goto unlock_mutex;
  }
  ep->sock_fd = -1;

  tmp_ret = cpc_query_receive(lib_handle, lib_handle->ctrl_sock_fd, NULL, sizeof(int));
  if (tmp_ret == 0) {
    TRACE_LIB(lib_handle, "closed EP #%d", ep->id);
  } else {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to receive close notification EP #%d, free up resources anyway", ep->id);
  }

  unlock_mutex:
  tmp_ret = pthread_mutex_unlock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed, free up resources anyway", &lib_handle->ctrl_sock_fd_lock);
  }

  destroy_mutex:
  tmp_ret = pthread_mutex_destroy(&ep->sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_destroy(%p) failed, free up resources anyway", &ep->sock_fd_lock);
  }

  // Try to close the file descriptor if an error occured previously and prevented it
  if (ep->sock_fd != -1 && close(ep->sock_fd) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "close(%d) failed", ep->sock_fd);
  }

  free(ep);
  endpoint->ptr = NULL;

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Attempt to read up to count bytes from a previously-opened endpoint socket.
 * Once data is received, it will be copied to the user-provided buffer.
 * The lifecycle of this buffer is handled by the user.
 *
 * By default the cpc_read function will block indefinitely.
 * A timeout can be configured with cpc_set_endpoint_option.
 ******************************************************************************/
ssize_t cpc_read_endpoint(cpc_endpoint_t endpoint, void *buffer, size_t count, cpc_endpoint_read_flags_t flags)
{
  INIT_CPC_RET(ssize_t);
  int sock_flags = 0;
  ssize_t bytes_read = 0;
  sli_cpc_endpoint_t *ep = NULL;

  if (buffer == NULL || count < SL_CPC_READ_MINIMUM_SIZE || endpoint.ptr == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  ep = (sli_cpc_endpoint_t *)endpoint.ptr;

  TRACE_LIB(ep->lib_handle, "reading from EP #%d", ep->id);

  if (flags & CPC_ENDPOINT_READ_FLAG_NON_BLOCKING) {
    sock_flags |= MSG_DONTWAIT;
  }

  bytes_read = recv(ep->sock_fd, buffer, count, sock_flags);
  if (bytes_read == 0) {
    TRACE_LIB_ERROR(ep->lib_handle, -ECONNRESET, "recv(%d) failed", ep->sock_fd);
    SET_CPC_RET(-ECONNRESET);
  } else if (bytes_read < 0) {
    if (errno != EAGAIN) {
      TRACE_LIB_ERRNO(ep->lib_handle, "recv(%d) failed", ep->sock_fd);
    }
    SET_CPC_RET(-errno);
  } else {
    SET_CPC_RET(bytes_read);
  }

  if (bytes_read > 0) {
    TRACE_LIB(ep->lib_handle, "read from EP #%d", ep->id);
  }

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Write data to an open endpoint.
 ******************************************************************************/
ssize_t cpc_write_endpoint(cpc_endpoint_t endpoint, const void *data, size_t data_length, cpc_endpoint_write_flags_t flags)
{
  INIT_CPC_RET(ssize_t);
  int sock_flags = 0;
  ssize_t bytes_written = 0;
  sli_cpc_endpoint_t *ep = NULL;

  if (endpoint.ptr == NULL || data == NULL || data_length == 0) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  ep = (sli_cpc_endpoint_t *)endpoint.ptr;

  if (data_length > ep->lib_handle->max_write_size) {
    TRACE_LIB_ERROR(ep->lib_handle, -EINVAL, "payload too large (%d > %d)", data_length, ep->lib_handle->max_write_size);
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  TRACE_LIB(ep->lib_handle, "writing to EP #%d", ep->id);

  if (flags & CPC_ENDPOINT_WRITE_FLAG_NON_BLOCKING) {
    sock_flags |= MSG_DONTWAIT;
  }

  bytes_written = send(ep->sock_fd, data, data_length, sock_flags);
  if (bytes_written == -1) {
    TRACE_LIB_ERRNO(ep->lib_handle, "send(%d) failed", ep->sock_fd);
    SET_CPC_RET(-errno);
    RETURN_CPC_RET;
  } else {
    SET_CPC_RET(bytes_written);
  }

  TRACE_LIB(ep->lib_handle, "wrote to EP #%d", ep->id);

  /*
   * The socket type between the library and the daemon are of type
   * SOCK_SEQPACKET. Unlike stream sockets, it is technically impossible
   * for DGRAM or SEQPACKET to do partial writes. The man page is ambiguous
   * about the return value in the our case, but research showed that it should
   * never happens. If it did happen,it would cause problems in
   * dealing with partially sent messages.
   */
  assert((size_t)bytes_written == data_length);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Get the state of an endpoint by ID.
 ******************************************************************************/
int cpc_get_endpoint_state(cpc_handle_t handle, uint8_t id, cpc_endpoint_state_t *state)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  sli_cpc_handle_t *lib_handle = NULL;

  if (state == NULL || handle.ptr == NULL || id == SL_CPC_ENDPOINT_SYSTEM) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lib_handle = (sli_cpc_handle_t *)handle.ptr;

  tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_lock(%p) failed", &lib_handle->ctrl_sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
    RETURN_CPC_RET;
  }

  TRACE_LIB(lib_handle, "get state EP #%d", id);

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_ENDPOINT_STATUS_QUERY, id,
                               (void*)state, sizeof(cpc_endpoint_state_t));

  tmp_ret = pthread_mutex_unlock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed", &lib_handle->ctrl_sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
    RETURN_CPC_RET;
  }

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Configure an endpoint with a specified option.
 ******************************************************************************/
int cpc_set_endpoint_option(cpc_endpoint_t endpoint, cpc_option_t option, const void *optval, size_t optlen)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  sli_cpc_endpoint_t *ep = NULL;

  if (option == CPC_OPTION_NONE || endpoint.ptr == NULL || optval == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  ep = (sli_cpc_endpoint_t *)endpoint.ptr;

  if (option == CPC_OPTION_RX_TIMEOUT) {
    cpc_timeval_t *useropt = (cpc_timeval_t*)optval;
    struct timeval sockopt;

    if (optlen != sizeof(cpc_timeval_t)) {
      TRACE_LIB_ERROR(ep->lib_handle, -EINVAL, "optval must be of type cpc_timeval_t");
      SET_CPC_RET(-EINVAL);
      RETURN_CPC_RET;
    }

    sockopt.tv_sec  = useropt->seconds;
    sockopt.tv_usec = useropt->microseconds;

    tmp_ret = setsockopt(ep->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &sockopt, (socklen_t)sizeof(sockopt));
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(ep->lib_handle, "setsockopt(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);
      RETURN_CPC_RET;
    }
  } else if (option == CPC_OPTION_TX_TIMEOUT) {
    cpc_timeval_t *useropt = (cpc_timeval_t*)optval;
    struct timeval sockopt;

    if (optlen != sizeof(cpc_timeval_t)) {
      TRACE_LIB_ERROR(ep->lib_handle, -EINVAL, "optval must be of type cpc_timeval_t");
      SET_CPC_RET(-EINVAL);
      RETURN_CPC_RET;
    }

    sockopt.tv_sec  = useropt->seconds;
    sockopt.tv_usec = useropt->microseconds;

    tmp_ret = setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDTIMEO, &sockopt, (socklen_t)sizeof(sockopt));
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(ep->lib_handle, "setsockopt(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);
      RETURN_CPC_RET;
    }
  } else if (option == CPC_OPTION_BLOCKING) {
    if (optlen != sizeof(bool)) {
      TRACE_LIB_ERROR(ep->lib_handle, -EINVAL, "optval must be of type bool");
      SET_CPC_RET(-EINVAL);
      RETURN_CPC_RET;
    }

    tmp_ret = pthread_mutex_lock(&ep->sock_fd_lock);
    if (tmp_ret != 0) {
      TRACE_LIB_ERROR(ep->lib_handle, -tmp_ret, "pthread_mutex_lock(%p) failed", &ep->sock_fd_lock);
      SET_CPC_RET(-tmp_ret);
      RETURN_CPC_RET;
    }

    int flags = fcntl(ep->sock_fd, F_GETFL);
    if (flags < 0) {
      TRACE_LIB_ERRNO(ep->lib_handle, "fnctl(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);

      tmp_ret = pthread_mutex_unlock(&ep->sock_fd_lock);
      if (tmp_ret != 0) {
        TRACE_LIB_ERROR(ep->lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed", &ep->sock_fd_lock);
        SET_CPC_RET(-tmp_ret);
      }

      RETURN_CPC_RET;
    }

    if (*(bool*)optval == true) {
      flags &= ~O_NONBLOCK;
    } else {
      flags |= O_NONBLOCK;
    }

    tmp_ret = fcntl(ep->sock_fd, F_SETFL, flags);
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(ep->lib_handle, "fnctl(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);
    }

    tmp_ret = pthread_mutex_unlock(&ep->sock_fd_lock);
    if (tmp_ret != 0) {
      TRACE_LIB_ERROR(ep->lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed", &ep->sock_fd_lock);
      SET_CPC_RET(-tmp_ret);
    }

    RETURN_CPC_RET;
  } else if (option == CPC_OPTION_SOCKET_SIZE) {
    if (optlen != sizeof(int)) {
      TRACE_LIB_ERROR(ep->lib_handle, -EINVAL, "optval must be of type int");
      SET_CPC_RET(-EINVAL);
      RETURN_CPC_RET;
    }

    if (setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, optval, (socklen_t)optlen) != 0) {
      TRACE_LIB_ERRNO(ep->lib_handle, "setsockopt(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);
      RETURN_CPC_RET;
    }
  } else {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Get the option configured for a specified endpoint.
 ******************************************************************************/
int cpc_get_endpoint_option(cpc_endpoint_t endpoint, cpc_option_t option, void *optval, size_t *optlen)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  sli_cpc_endpoint_t *ep = NULL;

  if (option == CPC_OPTION_NONE || endpoint.ptr == NULL || optval == NULL || optlen == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  ep = (sli_cpc_endpoint_t *)endpoint.ptr;

  if (option == CPC_OPTION_RX_TIMEOUT) {
    cpc_timeval_t *useropt = (cpc_timeval_t*)optval;
    struct timeval sockopt;
    socklen_t socklen = sizeof(sockopt);

    if (*optlen != sizeof(cpc_timeval_t)) {
      TRACE_LIB_ERROR(ep->lib_handle, -EINVAL, "optval must be of type cpc_timeval_t");
      SET_CPC_RET(-EINVAL);
      RETURN_CPC_RET;
    }

    tmp_ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &sockopt, &socklen);
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(ep->lib_handle, "getsockopt(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);
      RETURN_CPC_RET;
    }

    // these values are "usually" of type long, so make sure they
    // fit in integers (really, they should).
    if (sockopt.tv_sec > INT_MAX || sockopt.tv_usec > INT_MAX) {
      TRACE_LIB_ERROR(ep->lib_handle, -EINVAL, "getsockopt returned value out of bound");
      SET_CPC_RET(-EINVAL);
      RETURN_CPC_RET;
    }

    useropt->seconds      = (int)sockopt.tv_sec;
    useropt->microseconds = (int)sockopt.tv_usec;
  } else if (option == CPC_OPTION_TX_TIMEOUT) {
    cpc_timeval_t *useropt = (cpc_timeval_t*)optval;
    struct timeval sockopt;
    socklen_t socklen = sizeof(sockopt);

    if (*optlen != sizeof(cpc_timeval_t)) {
      TRACE_LIB_ERROR(ep->lib_handle, -EINVAL, "optval must be of type cpc_timeval_t");
      SET_CPC_RET(-EINVAL);
      RETURN_CPC_RET;
    }

    tmp_ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDTIMEO, &sockopt, &socklen);
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(ep->lib_handle, "getsockopt(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);
      RETURN_CPC_RET;
    }

    if (sockopt.tv_sec > INT_MAX || sockopt.tv_usec > INT_MAX) {
      TRACE_LIB_ERROR(ep->lib_handle, -EINVAL, "getsockopt returned value out of bound");
      SET_CPC_RET(-EINVAL);
      RETURN_CPC_RET;
    }

    useropt->seconds      = (int)sockopt.tv_sec;
    useropt->microseconds = (int)sockopt.tv_usec;
  } else if (option == CPC_OPTION_BLOCKING) {
    if (*optlen < sizeof(bool)) {
      TRACE_LIB_ERROR(ep->lib_handle, -ENOMEM, "insufficient space to store option value");
      SET_CPC_RET(-ENOMEM);
      RETURN_CPC_RET;
    }

    *optlen = sizeof(bool);

    int flags = fcntl(ep->sock_fd, F_GETFL);
    if (flags < 0) {
      TRACE_LIB_ERRNO(ep->lib_handle, "fnctl(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);
      RETURN_CPC_RET;
    }

    if (flags & O_NONBLOCK) {
      *(bool *)optval = false;
    } else {
      *(bool *)optval = true;
    }
  } else if (option == CPC_OPTION_SOCKET_SIZE) {
    socklen_t socklen = (socklen_t)*optlen;

    if (*optlen < sizeof(int)) {
      TRACE_LIB_ERROR(ep->lib_handle, -ENOMEM, "insufficient space to store option value");
      SET_CPC_RET(-ENOMEM);
      RETURN_CPC_RET;
    }

    tmp_ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, optval, &socklen);
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(ep->lib_handle, "getsockopt(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);
      RETURN_CPC_RET;
    }

    *optlen = (size_t)socklen;
  } else if (option == CPC_OPTION_MAX_WRITE_SIZE) {
    *optlen = sizeof(size_t);
    memcpy(optval, &ep->lib_handle->max_write_size, sizeof(ep->lib_handle->max_write_size));
  } else if (option == CPC_OPTION_ENCRYPTED) {
    if (*optlen < sizeof(bool)) {
      TRACE_LIB_ERROR(ep->lib_handle, -ENOMEM, "insufficient space to store option value");
      SET_CPC_RET(-ENOMEM);
      RETURN_CPC_RET;
    }

    tmp_ret = get_endpoint_encryption(ep, (bool*)optval);
    if (tmp_ret) {
      TRACE_LIB_ERROR(ep->lib_handle, tmp_ret, "failed to query endpoint encryption state");
      SET_CPC_RET(tmp_ret);
      RETURN_CPC_RET;
    }

    *optlen = sizeof(bool);
  } else {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Get the library version
 ******************************************************************************/
const char* cpc_get_library_version(void)
{
  return PROJECT_VER;
}

/***************************************************************************//**
 * Get the secondary application version
 ******************************************************************************/
const char* cpc_get_secondary_app_version(cpc_handle_t handle)
{
  sli_cpc_handle_t *lib_handle = NULL;
  char *secondary_app_version = NULL;
  size_t secondary_app_version_len = 0;

  if (handle.ptr == NULL) {
    return secondary_app_version;
  }

  lib_handle = (sli_cpc_handle_t *)handle.ptr;

  if (lib_handle->secondary_app_version == NULL) {
    return secondary_app_version;
  }

  secondary_app_version_len = strlen(lib_handle->secondary_app_version) + 1;
  secondary_app_version = zalloc(secondary_app_version_len);
  if (secondary_app_version == NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%d) failed", secondary_app_version_len);
  } else {
    memcpy(secondary_app_version, lib_handle->secondary_app_version, secondary_app_version_len);
  }

  return secondary_app_version;
}

/***************************************************************************//**
 * Free the secondary application version
 ******************************************************************************/
int cpc_free_secondary_app_version(char *secondary_app_version)
{
  INIT_CPC_RET(int);

  if (secondary_app_version == NULL) {
    SET_CPC_RET(-EINVAL);
  } else {
    free(secondary_app_version);
  }

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Set the timeout for the endpoint read operations
 ******************************************************************************/
int cpc_set_endpoint_read_timeout(cpc_endpoint_t endpoint, cpc_timeval_t timeval)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;

  tmp_ret = cpc_set_endpoint_option(endpoint, CPC_OPTION_RX_TIMEOUT, &timeval, sizeof(timeval));
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Set the timeout for the endpoint write operations
 ******************************************************************************/
int cpc_set_endpoint_write_timeout(cpc_endpoint_t endpoint, cpc_timeval_t timeval)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;

  tmp_ret = cpc_set_endpoint_option(endpoint, CPC_OPTION_TX_TIMEOUT, &timeval, sizeof(timeval));
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Select the blocking mode for the endpoint read and write operations
 ******************************************************************************/
int cpc_set_endpoint_blocking(cpc_endpoint_t endpoint, bool blocking)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;

  tmp_ret = cpc_set_endpoint_option(endpoint, CPC_OPTION_BLOCKING, &blocking, sizeof(bool));
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Set the socket size for write operations
 ******************************************************************************/
int cpc_set_endpoint_socket_size(cpc_endpoint_t endpoint, uint32_t socket_size)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;

  tmp_ret = cpc_set_endpoint_option(endpoint, CPC_OPTION_SOCKET_SIZE, &socket_size, sizeof(socket_size));
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Get the timeout for the endpoint read operations
 ******************************************************************************/
int cpc_get_endpoint_read_timeout(cpc_endpoint_t endpoint, cpc_timeval_t *timeval)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  size_t dummy = sizeof(cpc_timeval_t);

  tmp_ret = cpc_get_endpoint_option(endpoint, CPC_OPTION_RX_TIMEOUT, timeval, &dummy);
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Get the timeout for the endpoint write operations
 ******************************************************************************/
int cpc_get_endpoint_write_timeout(cpc_endpoint_t endpoint, cpc_timeval_t *timeval)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  size_t dummy = sizeof(cpc_timeval_t);

  tmp_ret = cpc_get_endpoint_option(endpoint, CPC_OPTION_TX_TIMEOUT, timeval, &dummy);
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Get the blocking mode for the endpoint read and write operations
 ******************************************************************************/
int cpc_get_endpoint_blocking_mode(cpc_endpoint_t endpoint, bool *is_blocking)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  size_t dummy = sizeof(bool);

  tmp_ret = cpc_get_endpoint_option(endpoint, CPC_OPTION_BLOCKING, is_blocking, &dummy);
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Get the socket size for write operations
 ******************************************************************************/
int cpc_get_endpoint_socket_size(cpc_endpoint_t endpoint, uint32_t * socket_size)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  size_t dummy = sizeof(uint32_t);

  tmp_ret = cpc_get_endpoint_option(endpoint, CPC_OPTION_SOCKET_SIZE, socket_size, &dummy);
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Get the maximum size of allowed for a single write operation.
 ******************************************************************************/
int cpc_get_endpoint_max_write_size(cpc_endpoint_t endpoint, size_t *max_write_size)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  size_t dummy = sizeof(size_t);

  tmp_ret = cpc_get_endpoint_option(endpoint, CPC_OPTION_MAX_WRITE_SIZE, max_write_size, &dummy);
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Get the encryption state for the provided endpoint.
 ******************************************************************************/
int cpc_get_endpoint_encryption_state(cpc_endpoint_t endpoint, bool *is_encrypted)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  size_t dummy = sizeof(bool);

  tmp_ret = cpc_get_endpoint_option(endpoint, CPC_OPTION_ENCRYPTED, is_encrypted, &dummy);
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Init the event handle for endpoint events
 ******************************************************************************/
int cpc_init_endpoint_event(cpc_handle_t handle, cpc_endpoint_event_handle_t *event_handle, uint8_t endpoint_id)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  sli_cpc_handle_t *lib_handle = NULL;
  sli_cpc_endpoint_event_handle_t *evt = NULL;
  struct sockaddr_un ep_event_addr = { 0 };

  if (handle.ptr == NULL || event_handle == NULL || endpoint_id == SL_CPC_ENDPOINT_SYSTEM) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lib_handle = (sli_cpc_handle_t *)handle.ptr;

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_OPEN_ENDPOINT_EVENT_SOCKET_QUERY, endpoint_id,
                               NULL, 0);
  if (tmp_ret) {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed exchange open endpoint event socket");
    SET_CPC_RET(tmp_ret);
    RETURN_CPC_RET;
  }

  evt = zalloc(sizeof(sli_cpc_endpoint_event_handle_t));
  if (evt == NULL) {
    TRACE_LIB_ERROR(evt->lib_handle, -ENOMEM, "alloc(%d) failed", sizeof(sli_cpc_endpoint_event_handle_t));
    SET_CPC_RET(-ENOMEM);
    RETURN_CPC_RET;
  }

  /* Save endpoint id for further use */
  evt->endpoint_id = endpoint_id;

  ep_event_addr.sun_family = AF_UNIX;

  /* Create the endpoint socket path */
  {
    int nchars;
    const size_t size = sizeof(ep_event_addr.sun_path) - 1;

    nchars = snprintf(ep_event_addr.sun_path, size, "%s/cpcd/%s/ep%d.event.cpcd.sock", CPC_SOCKET_DIR, lib_handle->instance_name, endpoint_id);

    /* Make sure the path fitted entirely in the struct sockaddr_un's static buffer */
    if (nchars < 0 || (size_t) nchars >= size) {
      TRACE_LIB_ERROR(lib_handle, -ERANGE, "socket path '%s/cpcd/%s/ep%d.event.cpcd.sock' does not fit in buffer", CPC_SOCKET_DIR, lib_handle->instance_name, endpoint_id);
      SET_CPC_RET(-ERANGE);
      goto free_event;
    }
  }

  evt->sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (evt->sock_fd < 0) {
    TRACE_LIB_ERRNO(lib_handle, "socket() failed");
    SET_CPC_RET(-errno);
    goto free_event;
  }

  tmp_ret = connect(evt->sock_fd, (struct sockaddr *)&ep_event_addr, sizeof(ep_event_addr));
  if (tmp_ret < 0) {
    TRACE_LIB_ERRNO(lib_handle, "connect(%d) failed", evt->sock_fd);
    SET_CPC_RET(-errno);
    goto close_sock_fd;
  }

  tmp_ret = pthread_mutex_init(&evt->sock_fd_lock, NULL);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_init(%p) failed", &evt->sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
    goto close_sock_fd;
  }

  TRACE_LIB(lib_handle, "endpoint %d event socket is connected", endpoint_id);

  evt->lib_handle = lib_handle;
  event_handle->ptr = (void*)evt;

  SET_CPC_RET(evt->sock_fd);
  RETURN_CPC_RET;

  close_sock_fd:
  if (close(evt->sock_fd) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "close(%d) failed", evt->sock_fd);
    SET_CPC_RET(-errno);
  }

  free_event:
  free(evt);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Read events on an endpoint
 ******************************************************************************/
int cpc_read_endpoint_event(cpc_endpoint_event_handle_t event_handle, cpc_event_type_t *event_type, cpc_endpoint_event_flags_t flags)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  ssize_t tmp_ret2 = 0;
  ssize_t event_length = 0;
  cpcd_event_buffer_t *event = NULL;
  sli_cpc_endpoint_event_handle_t *evt = NULL;
  int sock_flags = 0;

  if (event_handle.ptr == NULL || event_type == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  evt = (sli_cpc_endpoint_event_handle_t *)event_handle.ptr;

  if (evt->sock_fd <= 0) {
    TRACE_LIB_ERROR(evt->lib_handle, -EINVAL, "evt->sock_fd (%d) is not initialized", evt->sock_fd);
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  if (flags & CPC_ENDPOINT_EVENT_FLAG_NON_BLOCKING) {
    sock_flags |= MSG_DONTWAIT;
  }

  tmp_ret = pthread_mutex_lock(&evt->sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(evt->lib_handle, -tmp_ret, "pthread_mutex_lock(%p) failed", &evt->sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
    RETURN_CPC_RET;
  }

  // Get the size of the event and allocate a buffer accordingly
  tmp_ret2 = recv(evt->sock_fd, NULL, 0, sock_flags | MSG_PEEK | MSG_TRUNC);
  if (tmp_ret2 <= 0) {
    if (tmp_ret2 == -1) {
      TRACE_LIB_ERRNO(evt->lib_handle, "recv(%d) failed", evt->sock_fd);
      SET_CPC_RET(-errno);
    } else {
      TRACE_LIB_ERROR(evt->lib_handle, -EBADE, "recv(%d) failed, ret = %d", evt->sock_fd, tmp_ret2);
      SET_CPC_RET(-EBADE);
    }
    goto unlock_mutex;
  }

  event_length = tmp_ret2;

  event = zalloc((size_t)tmp_ret2);
  if (event ==  NULL) {
    TRACE_LIB_ERROR(evt->lib_handle, -ENOMEM, "alloc(%d) failed", tmp_ret2);
    SET_CPC_RET(-ENOMEM);
    goto unlock_mutex;
  }

  // Read the contents of the event socket
  tmp_ret2 = recv(evt->sock_fd, event, (size_t)event_length, 0);
  if (tmp_ret2 <= 0) {
    if (tmp_ret2 == -1) {
      TRACE_LIB_ERRNO(evt->lib_handle, "recv(%d) failed", evt->sock_fd);
      SET_CPC_RET(-errno);
    } else {
      TRACE_LIB_ERROR(evt->lib_handle, -EBADE, "recv(%d) failed, ret = %d", evt->sock_fd, tmp_ret2);
      SET_CPC_RET(-EBADE);
    }
    goto free_event;
  }

  *event_type = event->type;

  free_event:
  free(event);

  unlock_mutex:
  tmp_ret = pthread_mutex_unlock(&evt->sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(evt->lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed", &evt->sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
  }

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * De-init the endpoint event handle and any allocated resources
 ******************************************************************************/
int cpc_deinit_endpoint_event(cpc_endpoint_event_handle_t *event_handle)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  sli_cpc_endpoint_event_handle_t *evt = NULL;

  if (event_handle->ptr == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  evt = (sli_cpc_endpoint_event_handle_t*)event_handle->ptr;

  if (close(evt->sock_fd) < 0) {
    TRACE_LIB_ERRNO(evt->lib_handle, "close(%d) failed", evt->sock_fd);
  }

  tmp_ret = pthread_mutex_destroy(&evt->sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(evt->lib_handle, -tmp_ret, "pthread_mutex_destroy(%p) failed, free up resources anyway", &evt->sock_fd_lock);
  }

  TRACE_LIB(evt->lib_handle, "endpoint %d event socket is disconnected", evt->endpoint_id);

  free(evt);
  event_handle->ptr = NULL;

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Get the option configured for a specified endpoint event handle
 ******************************************************************************/
int cpc_get_endpoint_event_option(cpc_endpoint_event_handle_t event_handle, cpc_endpoint_event_option_t option, void *optval, size_t *optlen)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  sli_cpc_endpoint_event_handle_t *evt = NULL;

  if (option == CPC_ENDPOINT_EVENT_OPTION_NONE || event_handle.ptr == NULL || optval == NULL || optlen == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  evt = (sli_cpc_endpoint_event_handle_t*)event_handle.ptr;

  if (option == CPC_ENDPOINT_EVENT_OPTION_READ_TIMEOUT) {
    cpc_timeval_t *useropt = (cpc_timeval_t*)optval;
    struct timeval sockopt;
    socklen_t socklen = sizeof(sockopt);

    if (*optlen != sizeof(cpc_timeval_t)) {
      TRACE_LIB_ERROR(evt->lib_handle, -EINVAL, "optval must be of type cpc_timeval_t");
      SET_CPC_RET(-EINVAL);
      RETURN_CPC_RET;
    }

    tmp_ret = getsockopt(evt->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &sockopt, &socklen);
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(evt->lib_handle, "getsockopt(%d) failed", evt->sock_fd);
      SET_CPC_RET(-errno);
      RETURN_CPC_RET;
    }

    // these values are "usually" of type long, so make sure they
    // fit in integers (really, they should).
    if (sockopt.tv_sec > INT_MAX || sockopt.tv_usec > INT_MAX) {
      TRACE_LIB_ERROR(evt->lib_handle, -EINVAL, "getsockopt returned value out of bound");
      SET_CPC_RET(-EINVAL);
      RETURN_CPC_RET;
    }

    useropt->seconds      = (int)sockopt.tv_sec;
    useropt->microseconds = (int)sockopt.tv_usec;
  } else if (option == CPC_ENDPOINT_EVENT_OPTION_BLOCKING) {
    if (*optlen < sizeof(bool)) {
      TRACE_LIB_ERROR(evt->lib_handle, -ENOMEM, "insufficient space to store option value");
      SET_CPC_RET(-EINVAL);
      RETURN_CPC_RET;
    }

    *optlen = sizeof(bool);

    int flags = fcntl(evt->sock_fd, F_GETFL);
    if (flags < 0) {
      TRACE_LIB_ERRNO(evt->lib_handle, "fnctl(%d) failed", evt->sock_fd);
      SET_CPC_RET(-errno);
      RETURN_CPC_RET;
    }

    if (flags & O_NONBLOCK) {
      *(bool *)optval = false;
    } else {
      *(bool *)optval = true;
    }
  }

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Configure an endpoint event handle with a specified option.
 ******************************************************************************/
int cpc_set_endpoint_event_option(cpc_endpoint_event_handle_t event_handle, cpc_endpoint_event_option_t option, const void *optval, size_t optlen)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  sli_cpc_endpoint_event_handle_t *evt = NULL;

  if (option == CPC_ENDPOINT_EVENT_OPTION_NONE || event_handle.ptr == NULL || optval == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  evt = (sli_cpc_endpoint_event_handle_t*)event_handle.ptr;

  if (option == CPC_ENDPOINT_EVENT_OPTION_READ_TIMEOUT) {
    cpc_timeval_t *useropt = (cpc_timeval_t*)optval;
    struct timeval sockopt;

    if (optlen != sizeof(cpc_timeval_t)) {
      TRACE_LIB_ERROR(evt->lib_handle, -EINVAL, "optval must be of type cpc_timeval_t");
      SET_CPC_RET(-EINVAL);
      RETURN_CPC_RET;
    }

    sockopt.tv_sec  = useropt->seconds;
    sockopt.tv_usec = useropt->microseconds;

    tmp_ret = setsockopt(evt->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &sockopt, (socklen_t)sizeof(sockopt));
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(evt->lib_handle, "setsockopt(%d)", evt->sock_fd);
      SET_CPC_RET(-errno);
      RETURN_CPC_RET;
    }
  } else if (option == CPC_ENDPOINT_EVENT_OPTION_BLOCKING) {
    if (optlen != sizeof(bool)) {
      TRACE_LIB_ERROR(evt->lib_handle, -EINVAL, "optval must be of type bool");
      SET_CPC_RET(-EINVAL);
      RETURN_CPC_RET;
    }

    tmp_ret = pthread_mutex_lock(&evt->sock_fd_lock);
    if (tmp_ret != 0) {
      TRACE_LIB_ERROR(evt->lib_handle, -tmp_ret, "pthread_mutex_lock failed");
      SET_CPC_RET(-tmp_ret);
      RETURN_CPC_RET;
    }

    int flags = fcntl(evt->sock_fd, F_GETFL);
    if (flags < 0) {
      TRACE_LIB_ERRNO(evt->lib_handle, "fnctl(%d) failed", evt->sock_fd);
      SET_CPC_RET(-errno);

      tmp_ret = pthread_mutex_unlock(&evt->sock_fd_lock);
      if (tmp_ret != 0) {
        TRACE_LIB_ERROR(evt->lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed", &evt->sock_fd_lock);
        SET_CPC_RET(-tmp_ret);
      }

      RETURN_CPC_RET;
    }

    if (*(bool*)optval == true) {
      flags &= ~O_NONBLOCK;
    } else {
      flags |= O_NONBLOCK;
    }

    tmp_ret = fcntl(evt->sock_fd, F_SETFL, flags);
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(evt->lib_handle, "fnctl(%d) failed", evt->sock_fd);
      SET_CPC_RET(-errno);
    }

    tmp_ret = pthread_mutex_unlock(&evt->sock_fd_lock);
    if (tmp_ret != 0) {
      TRACE_LIB_ERROR(evt->lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed", &evt->sock_fd_lock);
      SET_CPC_RET(-tmp_ret);
    }

    RETURN_CPC_RET;
  } else {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Set the timeout for the endpoint event read operation
 ******************************************************************************/
int cpc_set_endpoint_event_read_timeout(cpc_endpoint_event_handle_t event_handle, cpc_timeval_t timeval)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;

  tmp_ret = cpc_set_endpoint_event_option(event_handle, CPC_ENDPOINT_EVENT_OPTION_READ_TIMEOUT, &timeval, sizeof(timeval));
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Get the timeout for the endpoint event read operation
 ******************************************************************************/
int cpc_get_endpoint_event_read_timeout(cpc_endpoint_event_handle_t event_handle, cpc_timeval_t *timeval)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  size_t dummy = sizeof(cpc_timeval_t);

  tmp_ret = cpc_get_endpoint_event_option(event_handle, CPC_ENDPOINT_EVENT_OPTION_READ_TIMEOUT, timeval, &dummy);
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Set the blocking mode for the endpoint event read operations
 ******************************************************************************/
int cpc_set_endpoint_event_blocking(cpc_endpoint_event_handle_t event_handle, bool blocking)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;

  tmp_ret = cpc_set_endpoint_event_option(event_handle, CPC_ENDPOINT_EVENT_OPTION_BLOCKING, &blocking, sizeof(blocking));
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}

/***************************************************************************//**
 * Get the blocking mode for the endpoint event read operations
 ******************************************************************************/
int cpc_get_endpoint_event_blocking_mode(cpc_endpoint_event_handle_t event_handle, bool *is_blocking)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  size_t dummy = sizeof(bool);

  tmp_ret = cpc_get_endpoint_event_option(event_handle, CPC_ENDPOINT_EVENT_OPTION_BLOCKING, is_blocking, &dummy);
  SET_CPC_RET(tmp_ret);

  RETURN_CPC_RET;
}
