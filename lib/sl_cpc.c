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

#include "config.h"

#include "sl_cpc.h"

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

#include "cpcd/event.h"
#include "cpcd/exchange.h"
#include "cpcd/sleep.h"
#include "cpcd/sl_slist.h"
#include "cpcd/utils.h"

#ifdef COMPILE_LTTNG
#include <lttng/tracef.h>
#define LTTNG_TRACE(string, ...)  tracef(string, ##__VA_ARGS__)
#else
#define LTTNG_TRACE(string, ...) (void)0
#endif

#define TIME_STR_LEN (27)

typedef struct {
  int ctrl_sock_fd;
  pthread_t reset_thread;
  int reset_sock_fd;
  cpc_reset_callback_t reset_callback;
  int ref_count;
  int ep_open_ref_count;
  int ep_evt_open_ref_count;
  pthread_mutex_t ctrl_sock_fd_lock;
  size_t max_write_size;
  char *secondary_app_version;
  bool enable_tracing;
  char* instance_name;
  bool initialized;
  pid_t pid;
} sli_cpc_handle_t;

typedef struct {
  uint8_t id;
  int session_id;
  int sock_fd;
  int ref_count;
  pthread_mutex_t sock_fd_lock;
  sli_cpc_handle_t *lib_handle;
} sli_cpc_endpoint_t;

typedef struct {
  uint8_t endpoint_id;
  int sock_fd;
  int ref_count;
  pthread_mutex_t sock_fd_lock;
  sli_cpc_handle_t *lib_handle;
} sli_cpc_endpoint_event_handle_t;

typedef struct {
  sl_slist_node_t node;
  void *handle;
} sli_handle_list_item_t;

static bool within_reset_callback(sli_cpc_handle_t *lib_handle)
{
  return lib_handle->reset_callback && pthread_equal(pthread_self(), lib_handle->reset_thread);
}

static size_t get_time_string(char *slice, size_t slice_len)
{
  int ret;
  struct timespec now;
  struct tm tm;

  if (slice_len < TIME_STR_LEN) {
    return 0;
  }

  ret = clock_gettime(CLOCK_REALTIME, &now);
  if (ret < 0) {
    return 0;
  }

  ret = gmtime_r(&now.tv_sec, &tm) == NULL;
  if (ret != 0) {
    return 0;
  }

  // XXXX-XX-XXTXX:XX:XX + .XXXXXX + Z
  strftime(slice, 19 + 1, "%FT%T", &tm);
  snprintf(slice + 19, 7 + 1, ".%06lu", (long)now.tv_nsec / 1000);
  slice[26] = 'Z';
  return TIME_STR_LEN;
}

__attribute__((format(printf, 2, 3))) static void lib_trace(FILE *__restrict __stream, const char* string, ...)
{
  va_list vl;
  va_start(vl, string);
  {
    vfprintf(__stream, string, vl);
    fflush(__stream);
  }
  va_end(vl);
}

#define TRACE_LIB_GENERIC(lib_handle, lib_trace_call, format, args ...)      \
  do {                                                                       \
    if (lib_handle->enable_tracing) {                                        \
      char time_string[TIME_STR_LEN + 1];                                    \
      int errno_backup = errno;                                              \
      time_string[get_time_string(time_string, sizeof(time_string))] = '\0'; \
      lib_trace_call;                                                        \
      LTTNG_TRACE("libcpc: " format "\n", ## args);                          \
      errno = errno_backup;                                                  \
    }                                                                        \
  } while (0)

#define TRACE_LIB(lib_handle, format, args ...)                                        \
  TRACE_LIB_GENERIC(lib_handle,                                                        \
                    lib_trace(stderr,                                                  \
                              "[%s] libcpc(%s:%d) [%s:%d]: " format "\n",              \
                              time_string, lib_handle->instance_name, lib_handle->pid, \
                              __FUNCTION__, __LINE__, ## args),                        \
                    format,                                                            \
                    args ...)                                                          \

// trace an error, "error" is expected to be a negative value of errno,
// eg. -EINVAL or -ENOMEM
#define TRACE_LIB_ERROR(lib_handle, error, format, args ...)                           \
  TRACE_LIB_GENERIC(lib_handle,                                                        \
                    lib_trace(stderr,                                                  \
                              "[%s] libcpc(%s:%d) [%s:%d]: " format " : errno %s\n",   \
                              time_string, lib_handle->instance_name, lib_handle->pid, \
                              __FUNCTION__, __LINE__, ## args, strerror(-error)),      \
                    format,                                                            \
                    args ...)                                                          \

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

#define CTRL_SOCKET_TIMEOUT_SEC 2

#define TX_WINDOW_SIZE_MIN 1
#define TX_WINDOW_SIZE_MAX 1

static sl_slist_node_t *lib_handle_list;
static sl_slist_node_t *ep_handle_list;
static sl_slist_node_t *ep_evt_handle_list;

static pthread_mutex_t cpc_api_lock = PTHREAD_MUTEX_INITIALIZER;

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
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%zd) failed", query_len);
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
      TRACE_LIB_ERROR(lib_handle, -EBADE, "send(%d) failed, ret = %zd", fd, bytes_written);
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
      TRACE_LIB_ERROR(lib_handle, -EBADE, "recv(%d) failed, ret = %zd", fd, bytes_read);
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
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%zd) failed", query_len);
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
      TRACE_LIB_ERROR(lib_handle, -EBADE, "recv(%d) failed, ret = %zd", fd, bytes_read);
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
    TRACE_LIB_ERROR(lib_handle, -ELIBBAD, "libcpc version (v%s) does not match the daemon version (v%s)", PROJECT_VER, version);
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
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%zd) failed", (size_t)app_string_size + 1);
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
  ssize_t bytes_written = 0;
  const size_t set_pid_query_len = sizeof(cpcd_exchange_buffer_t) + sizeof(pid_t);
  uint8_t buf[set_pid_query_len];
  cpcd_exchange_buffer_t* set_pid_query = (cpcd_exchange_buffer_t*)buf;

  set_pid_query->type = EXCHANGE_SET_PID_QUERY;
  set_pid_query->endpoint_number = 0;

  memcpy(set_pid_query->payload, &lib_handle->pid, sizeof(pid_t));

  bytes_written = send(lib_handle->ctrl_sock_fd, set_pid_query, set_pid_query_len, 0);
  if (bytes_written < (ssize_t)set_pid_query_len) {
    TRACE_LIB_ERRNO(lib_handle, "send(%d) failed", lib_handle->ctrl_sock_fd);
    SET_CPC_RET(-errno);
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

static void* cpc_reset_thread(void *handle)
{
  sli_cpc_handle_t *lib_handle = (sli_cpc_handle_t *) handle;
  uint8_t tmp;
  ssize_t ret;

  ret = read(lib_handle->reset_sock_fd, &tmp, sizeof(tmp));
  if (ret < 0) {
    TRACE_LIB_ERRNO(lib_handle, "read(%d) failed", lib_handle->reset_sock_fd);
  }

  if (lib_handle->initialized) {
    lib_handle->reset_callback();
  }

  return NULL;
}

static int lock_cpc_api(pthread_mutex_t *lock)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;

  tmp_ret = pthread_mutex_lock(lock);
  if (tmp_ret != 0) {
    SET_CPC_RET(-tmp_ret);
    RETURN_CPC_RET;
  }

  RETURN_CPC_RET;
}

static int unlock_cpc_api(pthread_mutex_t *lock)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;

  tmp_ret = pthread_mutex_unlock(lock);
  if (tmp_ret != 0) {
    SET_CPC_RET(-tmp_ret);
    RETURN_CPC_RET;
  }

  RETURN_CPC_RET;
}

static void increment_ref_count(int *ref_count)
{
  *ref_count = *ref_count + 1;
}

static void decrement_ref_count(int *ref_count)
{
  *ref_count = *ref_count - 1;
}

static sli_handle_list_item_t* find_handle(sl_slist_node_t *handle_list, void *handle)
{
  sli_handle_list_item_t *item = NULL;

  if (handle) {
    SL_SLIST_FOR_EACH_ENTRY(handle_list,
                            item,
                            sli_handle_list_item_t,
                            node) {
      if (item && item->handle == handle) {
        return item;
      }
    }
  }

  return NULL;
}

static int sli_cpc_deinit(bool atomic, cpc_handle_t *handle)
{
  INIT_CPC_RET(int);
  int tmp_ret = 0;
  sli_cpc_handle_t *lib_handle = NULL;
  sli_handle_list_item_t *lib_handle_item = NULL;

  if (handle == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  if (atomic) {
    lock_cpc_api(&cpc_api_lock);
  }

  lib_handle_item = find_handle(lib_handle_list, handle->ptr);
  if (lib_handle_item == NULL) {
    SET_CPC_RET(-EINVAL);
    goto cleanup;
  }

  lib_handle = (sli_cpc_handle_t *)handle->ptr;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    goto cleanup;
  }

  if (lib_handle->ref_count != 0) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot deinit a handle (%p) that is in use", handle);
    SET_CPC_RET(-EPERM);

    goto cleanup;
  }

  if (lib_handle->ep_open_ref_count != 0) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot deinit a handle (%p) with endpoint handles that are not closed", handle);
    SET_CPC_RET(-EPERM);

    goto cleanup;
  }

  if (lib_handle->ep_evt_open_ref_count != 0) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot deinit a handle (%p) with endpoint event handles that are not closed", handle);
    SET_CPC_RET(-EPERM);

    goto cleanup;
  }

  lib_handle->initialized = false;

  if (lib_handle->reset_callback) {
    if (shutdown(lib_handle->reset_sock_fd, SHUT_RD) < 0) {
      TRACE_LIB_ERRNO(lib_handle, "shutdown(%d) failed", lib_handle->reset_sock_fd);
    }

    if (close(lib_handle->reset_sock_fd) < 0) {
      TRACE_LIB_ERRNO(lib_handle, "close(%d) failed", lib_handle->reset_sock_fd);
    }

    tmp_ret = pthread_join(lib_handle->reset_thread, NULL);
    if (tmp_ret) {
      TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_join() failed");
    }
  }

  if (close(lib_handle->ctrl_sock_fd) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "close(%d) failed", lib_handle->ctrl_sock_fd);
  }

  tmp_ret = pthread_mutex_destroy(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_destroy(%p) failed, free up resources anyway", &lib_handle->ctrl_sock_fd_lock);
  }

  TRACE_LIB(lib_handle, "cpc lib deinitialized");

  sl_slist_remove(&lib_handle_list, &lib_handle_item->node);
  free(lib_handle_item);

  free(lib_handle->instance_name);
  free(lib_handle->secondary_app_version);
  free(lib_handle);
  handle->ptr = NULL;

  cleanup:
  if (atomic) {
    unlock_cpc_api(&cpc_api_lock);
  }

  RETURN_CPC_RET;
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
  sli_handle_list_item_t *lib_handle_item = NULL;
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

  lib_handle->pid = getpid();

  // Save the parameters internally for possible further re-init
  lib_handle->enable_tracing = enable_tracing;
  lib_handle->reset_callback = reset_callback;

  if (instance_name == NULL) {
    // If the instance name is NULL, use the default name
    lib_handle->instance_name = strdup(DEFAULT_INSTANCE_NAME);
    if (lib_handle->instance_name == NULL) {
      SET_CPC_RET(-errno);
      goto free_lib_handle;
    }
  } else {
    // Instead, use the one supplied by the user
    lib_handle->instance_name = strdup(instance_name);
    if (lib_handle->instance_name == NULL) {
      SET_CPC_RET(-errno);
      goto free_lib_handle;
    }
  }

  // Create the control socket path
  {
    int nchars;
    const size_t size = sizeof(server_addr.sun_path) - 1;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;

    nchars = snprintf(server_addr.sun_path, size, "%s/cpcd/%s/ctrl.cpcd.sock", CPC_SOCKET_DIR, lib_handle->instance_name);

    // Make sure the path fitted entirely in the struct's static buffer
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
  struct timeval timeout = { 0 };
  timeout.tv_sec = CTRL_SOCKET_TIMEOUT_SEC;
  timeout.tv_usec = 0;

  if (setsockopt(lib_handle->ctrl_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "setsockopt(%d) failed", lib_handle->ctrl_sock_fd);
    SET_CPC_RET(-errno);
    goto close_ctrl_sock_fd;
  }

  TRACE_LIB(lib_handle, "libcpc version: v%s", cpc_get_library_version());
  TRACE_LIB(lib_handle, "libcpc API version: v%d", LIBRARY_API_VERSION);

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

  lib_handle_item = zalloc(sizeof(sli_handle_list_item_t));
  if (lib_handle_item == NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%zd) failed", sizeof(sli_handle_list_item_t));
    SET_CPC_RET(-ENOMEM);
    goto destroy_mutex;
  }

  if (lib_handle->reset_callback) {
    // Create the reset socket path
    {
      int nchars;
      const size_t size = sizeof(server_addr.sun_path) - 1;
      memset(&server_addr, 0, sizeof(server_addr));
      server_addr.sun_family = AF_UNIX;

      nchars = snprintf(server_addr.sun_path, size, "%s/cpcd/%s/reset.cpcd.sock", CPC_SOCKET_DIR, lib_handle->instance_name);

      // Make sure the path fitted entirely in the struct's static buffer
      if (nchars < 0 || (size_t) nchars >= size) {
        TRACE_LIB_ERROR(lib_handle, -ERANGE, "socket path '%s/cpcd/%s/reset.cpcd.sock' does not fit in buffer", CPC_SOCKET_DIR, lib_handle->instance_name);
        SET_CPC_RET(-ERANGE);
        goto destroy_mutex;
      }
    }

    // Check if control socket exists
    if (access(server_addr.sun_path, F_OK) != 0) {
      TRACE_LIB_ERRNO(lib_handle,
                      "access() : %s doesn't exist. The daemon is not started or "
                      "the reset sequence is not done or the secondary is not responsive.",
                      server_addr.sun_path);
      SET_CPC_RET(-errno);
      goto destroy_mutex;
    }

    lib_handle->reset_sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (lib_handle->reset_sock_fd < 0) {
      TRACE_LIB_ERRNO(lib_handle, "socket() failed");
      SET_CPC_RET(-errno);
      goto destroy_mutex;
    }

    if (connect(lib_handle->reset_sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
      TRACE_LIB_ERRNO(lib_handle,
                      "connect() : could not connect to %s. Either the process does not have "
                      "the correct permissions or the secondary is not responsive.",
                      server_addr.sun_path);
      SET_CPC_RET(-errno);
      goto close_reset_sock_fd;
    }

    tmp_ret = pthread_create(&lib_handle->reset_thread, NULL, cpc_reset_thread, lib_handle);
    if (tmp_ret) {
      TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_create() failed");
      SET_CPC_RET(-tmp_ret);
      goto close_reset_sock_fd;
    }
  }

  lock_cpc_api(&cpc_api_lock);

  lib_handle_item->handle = lib_handle;
  lib_handle->initialized = true;
  handle->ptr = (void *)lib_handle;

  sl_slist_push(&lib_handle_list, &lib_handle_item->node);

  unlock_cpc_api(&cpc_api_lock);

  TRACE_LIB(lib_handle, "cpc lib initialized");

  RETURN_CPC_RET;

  close_reset_sock_fd:
  if (close(lib_handle->reset_sock_fd) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "close(%d) failed, free up resources anyway", lib_handle->reset_sock_fd);
    SET_CPC_RET(-errno);
  }

  destroy_mutex:
  tmp_ret = pthread_mutex_destroy(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_destroy(%p) failed, free up resources anyway", &lib_handle->ctrl_sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
  }

  free_secondary_app_version:
  free(lib_handle->secondary_app_version);

  close_ctrl_sock_fd:
  if (close(lib_handle->ctrl_sock_fd) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "close(%d) failed, free up resources anyway", lib_handle->ctrl_sock_fd);
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
  return sli_cpc_deinit(true, handle);
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
  sli_handle_list_item_t *lib_handle_item_copy = NULL;

  if (handle == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lock_cpc_api(&cpc_api_lock);

  if (find_handle(lib_handle_list, handle->ptr) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = (sli_cpc_handle_t *)handle->ptr;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  sli_cpc_handle_t *lib_handle_copy = zalloc(sizeof(sli_cpc_handle_t));
  if (lib_handle_copy == NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%zd) failed", sizeof(sli_cpc_handle_t));
    SET_CPC_RET(-ENOMEM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }
  memcpy(lib_handle_copy, lib_handle, sizeof(sli_cpc_handle_t));

  lib_handle_copy->instance_name = strdup(lib_handle->instance_name);
  if (lib_handle_copy->instance_name == NULL) {
    TRACE_LIB_ERRNO(lib_handle, "failed to copy the instance name");
    SET_CPC_RET(-errno);

    free(lib_handle_copy);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle_item_copy = zalloc(sizeof(sli_handle_list_item_t));
  if (lib_handle_item_copy == NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%zd) failed", sizeof(sli_handle_list_item_t));
    SET_CPC_RET(-ENOMEM);

    free(lib_handle_copy->instance_name);
    free(lib_handle_copy);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }
  lib_handle_item_copy->handle = lib_handle_copy;

  // De-init the original handle
  if (lib_handle_copy->initialized) {
    tmp_ret = sli_cpc_deinit(false, handle);
    if (tmp_ret != 0) {
      TRACE_LIB_ERROR(lib_handle, tmp_ret, "sli_cpc_deinit(%p) failed", handle);
      SET_CPC_RET(tmp_ret);

      free(lib_handle_copy->instance_name);
      free(lib_handle_copy);
      free(lib_handle_item_copy);

      unlock_cpc_api(&cpc_api_lock);
      RETURN_CPC_RET;
    }
  }

  unlock_cpc_api(&cpc_api_lock);

  // De-init was successful, invalidate copy
  lib_handle_copy->initialized = false;

  // Attemps a connection
  tmp_ret = cpc_init(handle, lib_handle_copy->instance_name, lib_handle_copy->enable_tracing, lib_handle_copy->reset_callback);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle_copy, tmp_ret, "cpc_init(%p, %s, %d, %p) failed, attempting again in %d milliseconds", handle, lib_handle_copy->instance_name, lib_handle_copy->enable_tracing, lib_handle_copy->reset_callback, CPCD_REBOOT_TIME_MS);
    sleep_ms(CPCD_REBOOT_TIME_MS);  // Wait for the minimum time it takes for CPCd to reboot

    tmp_ret = cpc_init(handle, lib_handle_copy->instance_name, lib_handle_copy->enable_tracing, lib_handle_copy->reset_callback);
    if (tmp_ret != 0) {
      SET_CPC_RET(tmp_ret);
      TRACE_LIB_ERROR(lib_handle_copy, tmp_ret, "cpc_init(%p, %s, %d, %p) failed", handle, lib_handle_copy->instance_name, lib_handle_copy->enable_tracing, lib_handle_copy->reset_callback);

      // Restore lib_handle
      handle->ptr = (void *)lib_handle_copy;

      lock_cpc_api(&cpc_api_lock);
      sl_slist_push(&lib_handle_list, &lib_handle_item_copy->node);
      unlock_cpc_api(&cpc_api_lock);

      RETURN_CPC_RET;
    }
  }

  free(lib_handle_copy->instance_name);
  free(lib_handle_copy);
  free(lib_handle_item_copy);

  RETURN_CPC_RET;
}
/***************************************************************************//**
 * Get a session id associated to this instance. This id is guaranteed to be
 * unique between all of the clients of a single endpoint on a single CPCd instance.
 ******************************************************************************/
int cpc_get_endpoint_session_id(cpc_endpoint_t endpoint, uint32_t *session_id)
{
  INIT_CPC_RET(int);
  sli_cpc_endpoint_t *ep = NULL;
  sli_cpc_handle_t *lib_handle = NULL;

  lock_cpc_api(&cpc_api_lock);

  if (find_handle(ep_handle_list, endpoint.ptr) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  ep = (sli_cpc_endpoint_t *)endpoint.ptr;
  if (find_handle(lib_handle_list, ep->lib_handle) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = ep->lib_handle;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  if (ep->session_id > INT32_MAX || ep->session_id < 0) {
    SET_CPC_RET(-ERANGE);
  } else {
    *session_id = (uint32_t)ep->session_id;
  }

  unlock_cpc_api(&cpc_api_lock);
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
  bool can_connect = false;
  sli_cpc_handle_t *lib_handle = NULL;
  sli_cpc_endpoint_t *ep = NULL;
  sli_handle_list_item_t *ep_handle_item = NULL;
  struct sockaddr_un ep_addr = { 0 };
  sl_cpc_open_endpoint_status_t status;
  uint8_t payload[sizeof(tx_window_size) + sizeof(status)];
  uint8_t payload2[sizeof(ep->session_id) + sizeof(can_connect)];

  if (id == SL_CPC_ENDPOINT_SYSTEM || endpoint == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lock_cpc_api(&cpc_api_lock);

  if (find_handle(lib_handle_list, handle.ptr) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = (sli_cpc_handle_t *)handle.ptr;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  increment_ref_count(&lib_handle->ref_count);

  unlock_cpc_api(&cpc_api_lock);

  if (tx_window_size < TX_WINDOW_SIZE_MIN || tx_window_size > TX_WINDOW_SIZE_MAX) {
    TRACE_LIB_ERROR(lib_handle,
                    -EINVAL,
                    "tx window must be in the %d-%d range",
                    TX_WINDOW_SIZE_MIN, TX_WINDOW_SIZE_MAX);
    SET_CPC_RET(-EINVAL);
    goto cleanup;
  }

  TRACE_LIB(lib_handle, "opening EP #%d", id);

  ep_addr.sun_family = AF_UNIX;

  // Create the endpoint socket path
  {
    int nchars;
    const size_t size = sizeof(ep_addr.sun_path) - 1;

    nchars = snprintf(ep_addr.sun_path, size, "%s/cpcd/%s/ep%d.cpcd.sock", CPC_SOCKET_DIR, lib_handle->instance_name, id);

    // Make sure the path fitted entirely in the struct sockaddr_un's static buffer
    if (nchars < 0 || (size_t) nchars >= size) {
      TRACE_LIB_ERROR(lib_handle, -ERANGE, "socket path '%s/cpcd/%s/ep%d.cpcd.sock' does not fit in buffer", CPC_SOCKET_DIR, lib_handle->instance_name, id);
      SET_CPC_RET(-ERANGE);
      goto cleanup;
    }
  }

  ep = zalloc(sizeof(sli_cpc_endpoint_t));
  if (ep == NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%zd) failed", sizeof(sli_cpc_endpoint_t));
    SET_CPC_RET(-ERANGE);
    goto cleanup;
  }

  tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_lock(%p) failed", &lib_handle->ctrl_sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
    goto free_endpoint;
  }

  payload[0] = tx_window_size;

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_OPEN_ENDPOINT_QUERY, id,
                               (void*)payload, sizeof(payload));

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

  memcpy(&status, &payload[1], sizeof(status));
  switch (status) {
    case SL_CPC_OPEN_ENDPOINT_SUCCESS:
      break;
    case SL_CPC_OPEN_ENDPOINT_ERROR_SECURITY:
      TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot open security endpoint as a client");
      SET_CPC_RET(-EPERM);
      goto free_endpoint;
    case SL_CPC_OPEN_ENDPOINT_ERROR_MULTICAST_DISABLED:
      TRACE_LIB_ERROR(lib_handle, -EACCES, "multicast is disabled for EP #%d", id);
      SET_CPC_RET(-EACCES);
      goto free_endpoint;
    case SL_CPC_OPEN_ENDPOINT_ERROR_GENERIC:
    default:
      TRACE_LIB_ERROR(lib_handle, -EAGAIN, "EP #%d on secondary is not opened", id);
      SET_CPC_RET(-EAGAIN);
      goto free_endpoint;
  }

  ep->sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (ep->sock_fd < 0) {
    TRACE_LIB_ERRNO(lib_handle, "socket()");
    SET_CPC_RET(-errno); goto free_endpoint;
  }

  tmp_ret = connect(ep->sock_fd, (struct sockaddr *)&ep_addr, sizeof(ep_addr));
  if (tmp_ret < 0) {
    TRACE_LIB_ERRNO(lib_handle, "connect(%d) failed", ep->sock_fd);
    SET_CPC_RET(-errno);
    goto close_sock_fd;
  }

  tmp_ret = cpc_query_receive(lib_handle, ep->sock_fd, (void*)payload2, sizeof(payload2));
  if (tmp_ret) {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to receive server ack");
    SET_CPC_RET(tmp_ret);
    goto close_sock_fd;
  }

  memcpy(&ep->session_id, payload2, sizeof(ep->session_id));
  memcpy(&can_connect, &payload2[sizeof(ep->session_id)], sizeof(can_connect));

  if (can_connect == false) {
    TRACE_LIB_ERROR(lib_handle, -EAGAIN, "endpoint on secondary did not accept connection request");
    SET_CPC_RET(-EAGAIN);
    goto close_sock_fd;
  }

  tmp_ret = pthread_mutex_init(&ep->sock_fd_lock, NULL);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_init(%p) failed", &ep->sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
    goto close_sock_fd;
  }

  ep_handle_item = zalloc(sizeof(sli_handle_list_item_t));
  if (ep_handle_item == NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%zd) failed", sizeof(sli_handle_list_item_t));
    SET_CPC_RET(-ENOMEM);
    goto destroy_mutex;
  }

  lock_cpc_api(&cpc_api_lock);

  ep_handle_item->handle = ep;
  sl_slist_push(&ep_handle_list, &ep_handle_item->node);
  increment_ref_count(&lib_handle->ep_open_ref_count);

  ep->id = id;
  ep->lib_handle = lib_handle;
  endpoint->ptr = (void *)ep;
  SET_CPC_RET(ep->sock_fd);

  unlock_cpc_api(&cpc_api_lock);

  TRACE_LIB(lib_handle, "opened EP #%d", ep->id);
  goto cleanup;

  destroy_mutex:
  tmp_ret = pthread_mutex_destroy(&ep->sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_destroy(%p) failed, free up resources anyway", &ep->sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
  }

  close_sock_fd:
  if (close(ep->sock_fd) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "close(%d) failed, free up resources anyway", ep->sock_fd);
    SET_CPC_RET(-errno);
  }

  free_endpoint:
  free(ep);

  cleanup:
  lock_cpc_api(&cpc_api_lock);
  decrement_ref_count(&lib_handle->ref_count);
  unlock_cpc_api(&cpc_api_lock);
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
  sli_handle_list_item_t *ep_handle_item = NULL;

  if (endpoint == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lock_cpc_api(&cpc_api_lock);

  ep_handle_item = find_handle(ep_handle_list, endpoint->ptr);
  if (ep_handle_item == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  ep = (sli_cpc_endpoint_t *)endpoint->ptr;
  if (find_handle(lib_handle_list, ep->lib_handle) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = ep->lib_handle;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  increment_ref_count(&lib_handle->ref_count);

  if (ep->ref_count != 0) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot close a handle (%p) that is in use", endpoint);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    goto cleanup;
  }

  sl_slist_remove(&ep_handle_list, &ep_handle_item->node);
  free(ep_handle_item);

  unlock_cpc_api(&cpc_api_lock);

  tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_lock(%p) failed, free up resources anyway", &lib_handle->ctrl_sock_fd_lock);
    goto destroy_mutex;
  }

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_CLOSE_ENDPOINT_QUERY, ep->id,
                               (void*)&ep->session_id, sizeof(ep->session_id));

  if (tmp_ret) {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to exchange close endpoint query, free up resources anyway");
  }

  TRACE_LIB(lib_handle, "closing EP #%d", ep->id);

  if (close(ep->sock_fd) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "close(%d) failed, free up resources anyway", ep->sock_fd);
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

  lock_cpc_api(&cpc_api_lock);

  free(ep);
  endpoint->ptr = NULL;

  decrement_ref_count(&lib_handle->ep_open_ref_count);

  unlock_cpc_api(&cpc_api_lock);

  cleanup:
  lock_cpc_api(&cpc_api_lock);
  decrement_ref_count(&lib_handle->ref_count);
  unlock_cpc_api(&cpc_api_lock);
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
  sli_cpc_handle_t *lib_handle = NULL;

  if (buffer == NULL || count < SL_CPC_READ_MINIMUM_SIZE) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lock_cpc_api(&cpc_api_lock);

  if (find_handle(ep_handle_list, endpoint.ptr) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  ep = (sli_cpc_endpoint_t *)endpoint.ptr;
  if (find_handle(lib_handle_list, ep->lib_handle) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = ep->lib_handle;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  increment_ref_count(&lib_handle->ref_count);
  increment_ref_count(&ep->ref_count);

  unlock_cpc_api(&cpc_api_lock);

  TRACE_LIB(lib_handle, "reading from EP #%d", ep->id);

  if (flags & CPC_ENDPOINT_READ_FLAG_NON_BLOCKING) {
    sock_flags |= MSG_DONTWAIT;
  }

  bytes_read = recv(ep->sock_fd, buffer, count, sock_flags);
  if (bytes_read == 0) {
    TRACE_LIB_ERROR(lib_handle, -ECONNRESET, "recv(%d) failed", ep->sock_fd);
    SET_CPC_RET(-ECONNRESET);
  } else if (bytes_read < 0) {
    if (errno != EAGAIN) {
      TRACE_LIB_ERRNO(lib_handle, "recv(%d) failed", ep->sock_fd);
    }
    SET_CPC_RET(-errno);
  } else {
    SET_CPC_RET(bytes_read);
  }

  if (bytes_read > 0) {
    TRACE_LIB(lib_handle, "read from EP #%d", ep->id);
  }

  lock_cpc_api(&cpc_api_lock);
  decrement_ref_count(&ep->ref_count);
  decrement_ref_count(&lib_handle->ref_count);
  unlock_cpc_api(&cpc_api_lock);
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
  sli_cpc_handle_t *lib_handle = NULL;

  if (data == NULL || data_length == 0) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lock_cpc_api(&cpc_api_lock);

  if (find_handle(ep_handle_list, endpoint.ptr) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  ep = (sli_cpc_endpoint_t *)endpoint.ptr;
  if (find_handle(lib_handle_list, ep->lib_handle) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = ep->lib_handle;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  increment_ref_count(&lib_handle->ref_count);
  increment_ref_count(&ep->ref_count);

  unlock_cpc_api(&cpc_api_lock);

  if (data_length > lib_handle->max_write_size) {
    TRACE_LIB_ERROR(lib_handle, -EINVAL, "payload too large (%zd > %zd)", data_length, lib_handle->max_write_size);
    SET_CPC_RET(-EINVAL);

    goto cleanup;
  }

  TRACE_LIB(lib_handle, "writing to EP #%d", ep->id);

  if (flags & CPC_ENDPOINT_WRITE_FLAG_NON_BLOCKING) {
    sock_flags |= MSG_DONTWAIT;
  }

  bytes_written = send(ep->sock_fd, data, data_length, sock_flags);
  if (bytes_written == -1) {
    TRACE_LIB_ERRNO(lib_handle, "send(%d) failed", ep->sock_fd);
    SET_CPC_RET(-errno);

    goto cleanup;
  } else {
    SET_CPC_RET(bytes_written);
  }

  TRACE_LIB(lib_handle, "wrote to EP #%d", ep->id);

  // The socket type between the library and the daemon are of type
  // SOCK_SEQPACKET. Unlike stream sockets, it is technically impossible
  // for DGRAM or SEQPACKET to do partial writes. The man page is ambiguous
  // about the return value in the our case, but research showed that it should
  // never happens. If it did happen,it would cause problems in
  // dealing with partially sent messages.
  assert((size_t)bytes_written == data_length);

  cleanup:
  lock_cpc_api(&cpc_api_lock);
  decrement_ref_count(&ep->ref_count);
  decrement_ref_count(&lib_handle->ref_count);
  unlock_cpc_api(&cpc_api_lock);
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

  if (state == NULL || id == SL_CPC_ENDPOINT_SYSTEM) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lock_cpc_api(&cpc_api_lock);

  if (find_handle(lib_handle_list, handle.ptr) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = (sli_cpc_handle_t *)handle.ptr;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  increment_ref_count(&lib_handle->ref_count);

  unlock_cpc_api(&cpc_api_lock);

  tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_lock(%p) failed", &lib_handle->ctrl_sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
    goto cleanup;
  }

  TRACE_LIB(lib_handle, "get state EP #%d", id);

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_ENDPOINT_STATUS_QUERY, id,
                               (void*)state, sizeof(cpc_endpoint_state_t));

  if (tmp_ret) {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to exchange endpoint state query");
    SET_CPC_RET(tmp_ret);
  }

  tmp_ret = pthread_mutex_unlock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed", &lib_handle->ctrl_sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
    goto cleanup;
  }

  cleanup:
  lock_cpc_api(&cpc_api_lock);
  decrement_ref_count(&lib_handle->ref_count);
  unlock_cpc_api(&cpc_api_lock);
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
  sli_cpc_handle_t *lib_handle = NULL;

  if (option == CPC_OPTION_NONE || optval == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lock_cpc_api(&cpc_api_lock);

  if (find_handle(ep_handle_list, endpoint.ptr) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  ep = (sli_cpc_endpoint_t *)endpoint.ptr;
  if (find_handle(lib_handle_list, ep->lib_handle) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = ep->lib_handle;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  increment_ref_count(&lib_handle->ref_count);
  increment_ref_count(&ep->ref_count);

  unlock_cpc_api(&cpc_api_lock);

  if (option == CPC_OPTION_RX_TIMEOUT) {
    cpc_timeval_t *useropt = (cpc_timeval_t*)optval;
    struct timeval sockopt = { 0 };

    if (optlen != sizeof(cpc_timeval_t)) {
      TRACE_LIB_ERROR(lib_handle, -EINVAL, "optval must be of type cpc_timeval_t");
      SET_CPC_RET(-EINVAL);

      goto cleanup;
    }

    sockopt.tv_sec  = useropt->seconds;
    sockopt.tv_usec = useropt->microseconds;

    tmp_ret = setsockopt(ep->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &sockopt, (socklen_t)sizeof(sockopt));
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(lib_handle, "setsockopt(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);

      goto cleanup;
    }
  } else if (option == CPC_OPTION_TX_TIMEOUT) {
    cpc_timeval_t *useropt = (cpc_timeval_t*)optval;
    struct timeval sockopt = { 0 };

    if (optlen != sizeof(cpc_timeval_t)) {
      TRACE_LIB_ERROR(lib_handle, -EINVAL, "optval must be of type cpc_timeval_t");
      SET_CPC_RET(-EINVAL);

      goto cleanup;
    }

    sockopt.tv_sec  = useropt->seconds;
    sockopt.tv_usec = useropt->microseconds;

    tmp_ret = setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDTIMEO, &sockopt, (socklen_t)sizeof(sockopt));
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(lib_handle, "setsockopt(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);

      goto cleanup;
    }
  } else if (option == CPC_OPTION_BLOCKING) {
    if (optlen != sizeof(bool)) {
      TRACE_LIB_ERROR(lib_handle, -EINVAL, "optval must be of type bool");
      SET_CPC_RET(-EINVAL);

      goto cleanup;
    }

    tmp_ret = pthread_mutex_lock(&ep->sock_fd_lock);
    if (tmp_ret != 0) {
      TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_lock(%p) failed", &ep->sock_fd_lock);
      SET_CPC_RET(-tmp_ret);

      goto cleanup;
    }

    int flags = fcntl(ep->sock_fd, F_GETFL);
    if (flags < 0) {
      TRACE_LIB_ERRNO(lib_handle, "fnctl(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);

      tmp_ret = pthread_mutex_unlock(&ep->sock_fd_lock);
      if (tmp_ret != 0) {
        TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed", &ep->sock_fd_lock);
        SET_CPC_RET(-tmp_ret);
      }

      goto cleanup;
    }

    if (*(bool*)optval == true) {
      flags &= ~O_NONBLOCK;
    } else {
      flags |= O_NONBLOCK;
    }

    tmp_ret = fcntl(ep->sock_fd, F_SETFL, flags);
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(lib_handle, "fnctl(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);
    }

    tmp_ret = pthread_mutex_unlock(&ep->sock_fd_lock);
    if (tmp_ret != 0) {
      TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed", &ep->sock_fd_lock);
      SET_CPC_RET(-tmp_ret);
    }

    goto cleanup;
  } else if (option == CPC_OPTION_SOCKET_SIZE) {
    if (optlen != sizeof(int)) {
      TRACE_LIB_ERROR(lib_handle, -EINVAL, "optval must be of type int");
      SET_CPC_RET(-EINVAL);
      goto cleanup;
    }

    if (setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, optval, (socklen_t)optlen) != 0) {
      TRACE_LIB_ERRNO(lib_handle, "setsockopt(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);
      goto cleanup;
    }
  } else {
    TRACE_LIB_ERROR(lib_handle, -EINVAL, "invalid endpoint option: %d", option);
    SET_CPC_RET(-EINVAL);
    goto cleanup;
  }

  cleanup:
  lock_cpc_api(&cpc_api_lock);
  decrement_ref_count(&ep->ref_count);
  decrement_ref_count(&lib_handle->ref_count);
  unlock_cpc_api(&cpc_api_lock);
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
  sli_cpc_handle_t *lib_handle = NULL;

  if (option == CPC_OPTION_NONE || optval == NULL || optlen == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lock_cpc_api(&cpc_api_lock);

  if (find_handle(ep_handle_list, endpoint.ptr) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  ep = (sli_cpc_endpoint_t *)endpoint.ptr;
  if (find_handle(lib_handle_list, ep->lib_handle) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = ep->lib_handle;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  increment_ref_count(&lib_handle->ref_count);
  increment_ref_count(&ep->ref_count);

  unlock_cpc_api(&cpc_api_lock);

  if (option == CPC_OPTION_RX_TIMEOUT) {
    cpc_timeval_t *useropt = (cpc_timeval_t*)optval;
    struct timeval sockopt = { 0 };
    socklen_t socklen = sizeof(sockopt);

    if (*optlen != sizeof(cpc_timeval_t)) {
      TRACE_LIB_ERROR(lib_handle, -EINVAL, "optval must be of type cpc_timeval_t");
      SET_CPC_RET(-EINVAL);

      goto cleanup;
    }

    tmp_ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &sockopt, &socklen);
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(lib_handle, "getsockopt(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);

      goto cleanup;
    }

    // these values are "usually" of type long, so make sure they
    // fit in integers (really, they should).
    if (sockopt.tv_sec > INT_MAX || sockopt.tv_usec > INT_MAX) {
      TRACE_LIB_ERROR(lib_handle, -EINVAL, "getsockopt returned value out of bound");
      SET_CPC_RET(-EINVAL);

      goto cleanup;
    }

    useropt->seconds      = (int)sockopt.tv_sec;
    useropt->microseconds = (int)sockopt.tv_usec;
  } else if (option == CPC_OPTION_TX_TIMEOUT) {
    cpc_timeval_t *useropt = (cpc_timeval_t*)optval;
    struct timeval sockopt = { 0 };
    socklen_t socklen = sizeof(sockopt);

    if (*optlen != sizeof(cpc_timeval_t)) {
      TRACE_LIB_ERROR(lib_handle, -EINVAL, "optval must be of type cpc_timeval_t");
      SET_CPC_RET(-EINVAL);

      goto cleanup;
    }

    tmp_ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDTIMEO, &sockopt, &socklen);
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(lib_handle, "getsockopt(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);

      goto cleanup;
    }

    if (sockopt.tv_sec > INT_MAX || sockopt.tv_usec > INT_MAX) {
      TRACE_LIB_ERROR(lib_handle, -EINVAL, "getsockopt returned value out of bound");
      SET_CPC_RET(-EINVAL);

      goto cleanup;
    }

    useropt->seconds      = (int)sockopt.tv_sec;
    useropt->microseconds = (int)sockopt.tv_usec;
  } else if (option == CPC_OPTION_BLOCKING) {
    if (*optlen < sizeof(bool)) {
      TRACE_LIB_ERROR(lib_handle, -ENOMEM, "insufficient space to store option value");
      SET_CPC_RET(-ENOMEM);

      goto cleanup;
    }

    *optlen = sizeof(bool);

    int flags = fcntl(ep->sock_fd, F_GETFL);
    if (flags < 0) {
      TRACE_LIB_ERRNO(lib_handle, "fnctl(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);

      goto cleanup;
    }

    if (flags & O_NONBLOCK) {
      *(bool *)optval = false;
    } else {
      *(bool *)optval = true;
    }
  } else if (option == CPC_OPTION_SOCKET_SIZE) {
    socklen_t socklen = (socklen_t)*optlen;

    if (*optlen < sizeof(int)) {
      TRACE_LIB_ERROR(lib_handle, -ENOMEM, "insufficient space to store option value");
      SET_CPC_RET(-ENOMEM);

      goto cleanup;
    }

    tmp_ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, optval, &socklen);
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(lib_handle, "getsockopt(%d) failed", ep->sock_fd);
      SET_CPC_RET(-errno);

      goto cleanup;
    }

    *optlen = (size_t)socklen;
  } else if (option == CPC_OPTION_MAX_WRITE_SIZE) {
    *optlen = sizeof(size_t);
    memcpy(optval, &lib_handle->max_write_size, sizeof(lib_handle->max_write_size));
  } else if (option == CPC_OPTION_ENCRYPTED) {
    if (*optlen < sizeof(bool)) {
      TRACE_LIB_ERROR(lib_handle, -ENOMEM, "insufficient space to store option value");
      SET_CPC_RET(-ENOMEM);

      goto cleanup;
    }

    tmp_ret = get_endpoint_encryption(ep, (bool*)optval);
    if (tmp_ret) {
      TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed to query endpoint encryption state");
      SET_CPC_RET(tmp_ret);

      goto cleanup;
    }

    *optlen = sizeof(bool);
  } else {
    TRACE_LIB_ERROR(lib_handle, -EINVAL, "invalid endpoint option: %d", option);
    SET_CPC_RET(-EINVAL);

    goto cleanup;
  }

  cleanup:
  lock_cpc_api(&cpc_api_lock);
  decrement_ref_count(&ep->ref_count);
  decrement_ref_count(&lib_handle->ref_count);
  unlock_cpc_api(&cpc_api_lock);
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

  lock_cpc_api(&cpc_api_lock);

  if (find_handle(lib_handle_list, handle.ptr) == NULL) {
    unlock_cpc_api(&cpc_api_lock);
    return secondary_app_version;
  }

  lib_handle = (sli_cpc_handle_t *)handle.ptr;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);

    unlock_cpc_api(&cpc_api_lock);
    return secondary_app_version;
  }

  increment_ref_count(&lib_handle->ref_count);

  unlock_cpc_api(&cpc_api_lock);

  if (lib_handle->secondary_app_version == NULL) {
    goto cleanup;
  }

  secondary_app_version_len = strlen(lib_handle->secondary_app_version) + 1;
  secondary_app_version = zalloc(secondary_app_version_len);
  if (secondary_app_version == NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%zd) failed", secondary_app_version_len);
  } else {
    memcpy(secondary_app_version, lib_handle->secondary_app_version, secondary_app_version_len);
  }

  cleanup:
  lock_cpc_api(&cpc_api_lock);
  decrement_ref_count(&lib_handle->ref_count);
  unlock_cpc_api(&cpc_api_lock);
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
  int tmp_ret2 = 0;
  sli_cpc_handle_t *lib_handle = NULL;
  sli_cpc_endpoint_event_handle_t *evt = NULL;
  sli_handle_list_item_t *ep_evt_handle_item = NULL;
  struct sockaddr_un ep_event_addr = { 0 };

  if (event_handle == NULL || endpoint_id == SL_CPC_ENDPOINT_SYSTEM) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lock_cpc_api(&cpc_api_lock);

  if (find_handle(lib_handle_list, handle.ptr) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = (sli_cpc_handle_t *)handle.ptr;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  increment_ref_count(&lib_handle->ref_count);

  unlock_cpc_api(&cpc_api_lock);

  tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_lock(%p) failed", &lib_handle->ctrl_sock_fd_lock);
    SET_CPC_RET(-tmp_ret);

    goto cleanup;
  }

  tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                               EXCHANGE_OPEN_ENDPOINT_EVENT_SOCKET_QUERY, endpoint_id,
                               NULL, 0);
  if (tmp_ret) {
    TRACE_LIB_ERROR(lib_handle, tmp_ret, "failed exchange open endpoint event socket");
    SET_CPC_RET(tmp_ret);
  }

  tmp_ret2 = pthread_mutex_unlock(&lib_handle->ctrl_sock_fd_lock);
  if (tmp_ret2 != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret2, "pthread_mutex_unlock(%p) failed", &lib_handle->ctrl_sock_fd_lock);
    SET_CPC_RET(-tmp_ret2);
    goto cleanup;
  }

  if (tmp_ret) {
    goto cleanup;
  }

  evt = zalloc(sizeof(sli_cpc_endpoint_event_handle_t));
  if (evt == NULL) {
    TRACE_LIB_ERROR(evt->lib_handle, -ENOMEM, "alloc(%zd) failed", sizeof(sli_cpc_endpoint_event_handle_t));
    SET_CPC_RET(-ENOMEM);

    goto cleanup;
  }

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

  ep_evt_handle_item = zalloc(sizeof(sli_handle_list_item_t));
  if (ep_evt_handle_item == NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%zd) failed", sizeof(sli_handle_list_item_t));
    SET_CPC_RET(-ENOMEM);
    goto destroy_mutex;
  }

  lock_cpc_api(&cpc_api_lock);

  ep_evt_handle_item->handle = evt;
  sl_slist_push(&ep_evt_handle_list, &ep_evt_handle_item->node);
  increment_ref_count(&lib_handle->ep_evt_open_ref_count);

  evt->endpoint_id = endpoint_id;
  evt->lib_handle = lib_handle;
  event_handle->ptr = (void *) evt;
  SET_CPC_RET(evt->sock_fd);

  unlock_cpc_api(&cpc_api_lock);

  TRACE_LIB(lib_handle, "endpoint %d event socket (%d) is connected", endpoint_id, evt->sock_fd);
  goto cleanup;

  destroy_mutex:
  tmp_ret = pthread_mutex_destroy(&evt->sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_destroy(%p) failed, free up resources anyway", &evt->sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
  }

  close_sock_fd:
  if (close(evt->sock_fd) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "close(%d) failed, free up resources anyway", evt->sock_fd);
    SET_CPC_RET(-errno);
  }

  free_event:
  free(evt);

  cleanup:
  lock_cpc_api(&cpc_api_lock);
  decrement_ref_count(&lib_handle->ref_count);
  unlock_cpc_api(&cpc_api_lock);
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
  sli_cpc_handle_t *lib_handle = NULL;
  int sock_flags = 0;

  if (event_type == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lock_cpc_api(&cpc_api_lock);

  if (find_handle(ep_evt_handle_list, event_handle.ptr) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  evt = (sli_cpc_endpoint_event_handle_t *)event_handle.ptr;
  if (find_handle(lib_handle_list, evt->lib_handle) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = evt->lib_handle;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  increment_ref_count(&lib_handle->ref_count);
  increment_ref_count(&evt->ref_count);

  unlock_cpc_api(&cpc_api_lock);

  if (evt->sock_fd <= 0) {
    TRACE_LIB_ERROR(lib_handle, -EINVAL, "evt->sock_fd (%d) is not initialized", evt->sock_fd);
    SET_CPC_RET(-EINVAL);

    goto cleanup;
  }

  if (flags & CPC_ENDPOINT_EVENT_FLAG_NON_BLOCKING) {
    sock_flags |= MSG_DONTWAIT;
  }

  tmp_ret = pthread_mutex_lock(&evt->sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_lock(%p) failed", &evt->sock_fd_lock);
    SET_CPC_RET(-tmp_ret);

    goto cleanup;
  }

  // Get the size of the event and allocate a buffer accordingly
  tmp_ret2 = recv(evt->sock_fd, NULL, 0, sock_flags | MSG_PEEK | MSG_TRUNC);
  if (tmp_ret2 <= 0) {
    if (tmp_ret2 == -1) {
      TRACE_LIB_ERRNO(lib_handle, "recv(%d) failed", evt->sock_fd);
      SET_CPC_RET(-errno);
    } else {
      TRACE_LIB_ERROR(lib_handle, -EBADE, "recv(%d) failed, ret = %zd", evt->sock_fd, tmp_ret2);
      SET_CPC_RET(-EBADE);
    }
    goto unlock_mutex;
  }

  event_length = tmp_ret2;

  event = zalloc((size_t)tmp_ret2);
  if (event ==  NULL) {
    TRACE_LIB_ERROR(lib_handle, -ENOMEM, "alloc(%zd) failed", tmp_ret2);
    SET_CPC_RET(-ENOMEM);
    goto unlock_mutex;
  }

  // Read the contents of the event socket
  tmp_ret2 = recv(evt->sock_fd, event, (size_t)event_length, 0);
  if (tmp_ret2 <= 0) {
    if (tmp_ret2 == -1) {
      TRACE_LIB_ERRNO(lib_handle, "recv(%d) failed", evt->sock_fd);
      SET_CPC_RET(-errno);
    } else {
      TRACE_LIB_ERROR(lib_handle, -EBADE, "recv(%d) failed, ret = %zd", evt->sock_fd, tmp_ret2);
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
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed", &evt->sock_fd_lock);
    SET_CPC_RET(-tmp_ret);
  }

  cleanup:
  lock_cpc_api(&cpc_api_lock);
  decrement_ref_count(&evt->ref_count);
  decrement_ref_count(&lib_handle->ref_count);
  unlock_cpc_api(&cpc_api_lock);
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
  sli_cpc_handle_t *lib_handle = NULL;
  sli_handle_list_item_t *ep_evt_handle_item = NULL;

  if (event_handle == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lock_cpc_api(&cpc_api_lock);

  ep_evt_handle_item = find_handle(ep_evt_handle_list, event_handle->ptr);
  if (ep_evt_handle_item == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  evt = (sli_cpc_endpoint_event_handle_t *)event_handle->ptr;
  if (find_handle(lib_handle_list, evt->lib_handle) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = evt->lib_handle;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  increment_ref_count(&lib_handle->ref_count);

  if (evt->ref_count != 0) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot close a handle (%p) that is in use", event_handle);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    goto cleanup;
  }

  sl_slist_remove(&ep_evt_handle_list, &ep_evt_handle_item->node);
  free(ep_evt_handle_item);

  unlock_cpc_api(&cpc_api_lock);

  if (close(evt->sock_fd) < 0) {
    TRACE_LIB_ERRNO(lib_handle, "close(%d) failed, free up resources anyway", evt->sock_fd);
  }

  tmp_ret = pthread_mutex_destroy(&evt->sock_fd_lock);
  if (tmp_ret != 0) {
    TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_destroy(%p) failed, free up resources anyway", &evt->sock_fd_lock);
  }

  TRACE_LIB(lib_handle, "endpoint %d event socket (%d) is disconnected", evt->endpoint_id, evt->sock_fd);

  lock_cpc_api(&cpc_api_lock);

  free(evt);
  event_handle->ptr = NULL;

  decrement_ref_count(&lib_handle->ep_evt_open_ref_count);

  unlock_cpc_api(&cpc_api_lock);

  cleanup:
  lock_cpc_api(&cpc_api_lock);
  decrement_ref_count(&lib_handle->ref_count);
  unlock_cpc_api(&cpc_api_lock);
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
  sli_cpc_handle_t *lib_handle = NULL;

  if (option == CPC_ENDPOINT_EVENT_OPTION_NONE || optval == NULL || optlen == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lock_cpc_api(&cpc_api_lock);

  if (find_handle(ep_evt_handle_list, event_handle.ptr) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  evt = (sli_cpc_endpoint_event_handle_t *)event_handle.ptr;
  if (find_handle(lib_handle_list, evt->lib_handle) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = evt->lib_handle;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  increment_ref_count(&lib_handle->ref_count);
  increment_ref_count(&evt->ref_count);

  unlock_cpc_api(&cpc_api_lock);

  if (option == CPC_ENDPOINT_EVENT_OPTION_READ_TIMEOUT) {
    cpc_timeval_t *useropt = (cpc_timeval_t*)optval;
    struct timeval sockopt = { 0 };
    socklen_t socklen = sizeof(sockopt);

    if (*optlen != sizeof(cpc_timeval_t)) {
      TRACE_LIB_ERROR(lib_handle, -EINVAL, "optval must be of type cpc_timeval_t");
      SET_CPC_RET(-EINVAL);

      goto cleanup;
    }

    tmp_ret = getsockopt(evt->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &sockopt, &socklen);
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(lib_handle, "getsockopt(%d) failed", evt->sock_fd);
      SET_CPC_RET(-errno);

      goto cleanup;
    }

    // these values are "usually" of type long, so make sure they
    // fit in integers (really, they should).
    if (sockopt.tv_sec > INT_MAX || sockopt.tv_usec > INT_MAX) {
      TRACE_LIB_ERROR(lib_handle, -EINVAL, "getsockopt returned value out of bound");
      SET_CPC_RET(-EINVAL);

      goto cleanup;
    }

    useropt->seconds      = (int)sockopt.tv_sec;
    useropt->microseconds = (int)sockopt.tv_usec;
  } else if (option == CPC_ENDPOINT_EVENT_OPTION_BLOCKING) {
    if (*optlen < sizeof(bool)) {
      TRACE_LIB_ERROR(lib_handle, -ENOMEM, "insufficient space to store option value");
      SET_CPC_RET(-EINVAL);

      goto cleanup;
    }

    *optlen = sizeof(bool);

    int flags = fcntl(evt->sock_fd, F_GETFL);
    if (flags < 0) {
      TRACE_LIB_ERRNO(lib_handle, "fnctl(%d) failed", evt->sock_fd);
      SET_CPC_RET(-errno);

      goto cleanup;
    }

    if (flags & O_NONBLOCK) {
      *(bool *)optval = false;
    } else {
      *(bool *)optval = true;
    }
  } else {
    TRACE_LIB_ERROR(lib_handle, -EINVAL, "invalid endpoint event option: %d", option);
    SET_CPC_RET(-EINVAL);

    goto cleanup;
  }

  cleanup:
  lock_cpc_api(&cpc_api_lock);
  decrement_ref_count(&evt->ref_count);
  decrement_ref_count(&lib_handle->ref_count);
  unlock_cpc_api(&cpc_api_lock);
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
  sli_cpc_handle_t *lib_handle = NULL;

  if (option == CPC_ENDPOINT_EVENT_OPTION_NONE || optval == NULL) {
    SET_CPC_RET(-EINVAL);
    RETURN_CPC_RET;
  }

  lock_cpc_api(&cpc_api_lock);

  if (find_handle(ep_evt_handle_list, event_handle.ptr) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  evt = (sli_cpc_endpoint_event_handle_t *)event_handle.ptr;
  if (find_handle(lib_handle_list, evt->lib_handle) == NULL) {
    SET_CPC_RET(-EINVAL);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  lib_handle = evt->lib_handle;

  if (within_reset_callback(lib_handle)) {
    TRACE_LIB_ERROR(lib_handle, -EPERM, "cannot call %s within reset callback", __func__);
    SET_CPC_RET(-EPERM);

    unlock_cpc_api(&cpc_api_lock);
    RETURN_CPC_RET;
  }

  increment_ref_count(&lib_handle->ref_count);
  increment_ref_count(&evt->ref_count);

  unlock_cpc_api(&cpc_api_lock);

  if (option == CPC_ENDPOINT_EVENT_OPTION_READ_TIMEOUT) {
    cpc_timeval_t *useropt = (cpc_timeval_t*)optval;
    struct timeval sockopt = { 0 };

    if (optlen != sizeof(cpc_timeval_t)) {
      TRACE_LIB_ERROR(lib_handle, -EINVAL, "optval must be of type cpc_timeval_t");
      SET_CPC_RET(-EINVAL);

      goto cleanup;
    }

    sockopt.tv_sec  = useropt->seconds;
    sockopt.tv_usec = useropt->microseconds;

    tmp_ret = setsockopt(evt->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &sockopt, (socklen_t)sizeof(sockopt));
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(lib_handle, "setsockopt(%d)", evt->sock_fd);
      SET_CPC_RET(-errno);

      goto cleanup;
    }
  } else if (option == CPC_ENDPOINT_EVENT_OPTION_BLOCKING) {
    if (optlen != sizeof(bool)) {
      TRACE_LIB_ERROR(lib_handle, -EINVAL, "optval must be of type bool");
      SET_CPC_RET(-EINVAL);

      goto cleanup;
    }

    tmp_ret = pthread_mutex_lock(&evt->sock_fd_lock);
    if (tmp_ret != 0) {
      TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_lock failed");
      SET_CPC_RET(-tmp_ret);

      goto cleanup;
    }

    int flags = fcntl(evt->sock_fd, F_GETFL);
    if (flags < 0) {
      TRACE_LIB_ERRNO(lib_handle, "fnctl(%d) failed", evt->sock_fd);
      SET_CPC_RET(-errno);

      tmp_ret = pthread_mutex_unlock(&evt->sock_fd_lock);
      if (tmp_ret != 0) {
        TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed", &evt->sock_fd_lock);
        SET_CPC_RET(-tmp_ret);
      }

      goto cleanup;
    }

    if (*(bool*)optval == true) {
      flags &= ~O_NONBLOCK;
    } else {
      flags |= O_NONBLOCK;
    }

    tmp_ret = fcntl(evt->sock_fd, F_SETFL, flags);
    if (tmp_ret < 0) {
      TRACE_LIB_ERRNO(lib_handle, "fnctl(%d) failed", evt->sock_fd);
      SET_CPC_RET(-errno);
    }

    tmp_ret = pthread_mutex_unlock(&evt->sock_fd_lock);
    if (tmp_ret != 0) {
      TRACE_LIB_ERROR(lib_handle, -tmp_ret, "pthread_mutex_unlock(%p) failed", &evt->sock_fd_lock);
      SET_CPC_RET(-tmp_ret);
    }

    goto cleanup;
  } else {
    TRACE_LIB_ERROR(lib_handle, -EINVAL, "invalid endpoint event option: %d", option);
    SET_CPC_RET(-EINVAL);

    goto cleanup;
  }

  cleanup:
  lock_cpc_api(&cpc_api_lock);
  decrement_ref_count(&evt->ref_count);
  decrement_ref_count(&lib_handle->ref_count);
  unlock_cpc_api(&cpc_api_lock);
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
