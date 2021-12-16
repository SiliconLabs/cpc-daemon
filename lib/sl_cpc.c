/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) - Library Implementation
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <time.h>
#include <stdarg.h>

#include "sl_cpc.h"
#include "version.h"
#include "server_core/cpcd_exchange.h"

#ifdef COMPILE_LTTNG
#include <lttng/tracef.h>
#define LTTNG_TRACE(string, ...)  tracef(string, ##__VA_ARGS__)
#else
#define LTTNG_TRACE(string, ...) (void)0
#endif

static void lib_trace(FILE *__restrict __stream, const char* string, ...)
{
  char time_string[25];

  /* get time string */
  {
    long ms;
    time_t s;
    struct timespec spec;
    struct tm* tm_info;

    int ret = clock_gettime(CLOCK_REALTIME, &spec);

    s = spec.tv_sec;

    ms = spec.tv_nsec / 1000000;
    if (ms > 999) {
      s++;
      ms = 0;
    }

    if (ret != -1) {
      tm_info = localtime(&s);
      size_t r = strftime(time_string, sizeof(time_string), "%H:%M:%S", tm_info);
      sprintf(&time_string[r], ":%ld", ms);
    } else {
      strncpy(time_string, "time error", sizeof(time_string));
    }
  }

  fprintf(__stream, "[%s] ", time_string);

  va_list vl;

  va_start(vl, string);
  {
    vfprintf(__stream, string, vl);
    fflush(__stream);
  }
  va_end(vl);
}

#define trace_lib(format, args ...)                     \
  if (saved_enable_tracing) {                           \
    lib_trace(stderr, "libcpc: " format "\n", ## args); \
    LTTNG_TRACE("libcpc: " format "\n", ## args);       \
  }

#define trace_lib_error(format, args ...)                    \
  if (saved_enable_tracing) {                                \
    lib_trace(stderr, "libcpc: " format " : %m\n", ## args); \
    LTTNG_TRACE("libcpc: " format "\n", ## args);            \
  }

#ifndef DEFAULT_INSTANCE_NAME
  #define DEFAULT_INSTANCE_NAME "cpcd_0"
#endif

#define SOCK_DIR "/dev/shm"

#define CTRL_SOCKET_TIMEOUT_SEC 1

#define DEFAULT_ENDPOINT_SOCKET_SIZE 4087

typedef struct {
  int ctrl_sock_fd;
  size_t max_write_size;
} sli_cpc_handle_t;

typedef struct {
  uint8_t id;
  int sock_fd;
  sli_cpc_handle_t *lib_handle;
} sli_cpc_endpoint_t;

static bool saved_enable_tracing = false;
static char* saved_instance_name = NULL;
static cpc_reset_callback_t saved_reset_callback;

static ssize_t get_max_write(sli_cpc_handle_t *lib_handle)
{
  size_t max_write_size;
  ssize_t bytes_read, bytes_written;
  const size_t max_write_query_len = sizeof(cpcd_exchange_buffer_t) + sizeof(size_t);
  uint8_t buf[max_write_query_len];
  cpcd_exchange_buffer_t* max_write_query = (cpcd_exchange_buffer_t*)buf;

  max_write_query->type = EXCHANGE_MAX_WRITE_SIZE_QUERY;

  max_write_query->endpoint_number = 0;
  memset(max_write_query->payload, 0, sizeof(size_t));

  bytes_written = send(lib_handle->ctrl_sock_fd, max_write_query, max_write_query_len, 0);

  if (bytes_written < (ssize_t)max_write_query_len) {
    trace_lib_error("write()");
    return -1;
  }

  bytes_read = recv(lib_handle->ctrl_sock_fd, max_write_query, max_write_query_len, 0);
  if (bytes_read != (ssize_t)max_write_query_len) {
    trace_lib_error("recv()");
    return -1;
  }

  memcpy(&max_write_size, max_write_query->payload, sizeof(size_t));

  return (ssize_t)max_write_size;
}

static bool check_version(sli_cpc_handle_t *lib_handle)
{
  ssize_t bytes_read, bytes_written;
  const size_t version_query_len = sizeof(cpcd_exchange_buffer_t) + 2 * sizeof(uint32_t);
  uint8_t buf[version_query_len];
  cpcd_exchange_buffer_t* version_query = (cpcd_exchange_buffer_t*)buf;
  uint32_t* version = (uint32_t*) version_query->payload;

  version_query->type = EXCHANGE_VERSION_QUERY;
  version_query->endpoint_number = 0;//no effect
  version[0] = (uint32_t)PROJECT_VER_MAJOR;
  version[1] = (uint32_t)PROJECT_VER_MINOR;

  bytes_written = send(lib_handle->ctrl_sock_fd, version_query, version_query_len, 0);
  if (bytes_written < (ssize_t)version_query_len) {
    trace_lib_error("write() failed when matching libcpc version with the daemon");
    return false;
  }

  bytes_read = recv(lib_handle->ctrl_sock_fd, version_query, version_query_len, 0);
  if (bytes_read != (ssize_t)version_query_len) {
    trace_lib_error("recv() failed when matching libcpc version with the daemon");
    return false;
  }

  if (version[0] != PROJECT_VER_MAJOR || version[1] != PROJECT_VER_MINOR) {
    errno = ELIBBAD;
    return false;
  }

  return true;
}

static ssize_t set_pid(sli_cpc_handle_t *lib_handle)
{
  const size_t set_pid_query_len = sizeof(cpcd_exchange_buffer_t) + sizeof(pid_t);
  uint8_t buf[set_pid_query_len];
  cpcd_exchange_buffer_t* set_pid_query = (cpcd_exchange_buffer_t*)buf;
  ssize_t bytes_written;
  pid_t pid = getpid();

  set_pid_query->type = EXCHANGE_SET_PID_QUERY;

  set_pid_query->endpoint_number = 0;

  memcpy(set_pid_query->payload, &pid, sizeof(pid_t));

  bytes_written = send(lib_handle->ctrl_sock_fd, set_pid_query, set_pid_query_len, 0);
  if (bytes_written < (ssize_t)set_pid_query_len) {
    trace_lib_error("write()");
    return -1;
  }

  return (ssize_t)0;
}

static void SIGUSR1_handler(int signum)
{
  (void) signum;

  if (saved_reset_callback != NULL) {
    saved_reset_callback();
  }
}
/***************************************************************************/ /**
 * Initialize the CPC library.
 * Upon success the user will obtain a handle that must be passed to cpc_open calls.
 * The library will use this handle to save information that are private to libcpc.
 ******************************************************************************/
int cpc_init(cpc_handle_t *handle, const char* instance_name, bool enable_tracing, cpc_reset_callback_t reset_callback)
{
  ssize_t ret;
  sli_cpc_handle_t *lib_handle;
  struct sockaddr_un server_addr;

  /* Clear struct for portability */
  memset(&server_addr, 0, sizeof(server_addr));

  server_addr.sun_family = AF_UNIX;

  /* Save the parameters internally for possible further re-init */
  {
    saved_enable_tracing = enable_tracing;

    saved_reset_callback = reset_callback;

    /* Skip this step if cpc_init is called again, like in the context of a reset */
    if (saved_instance_name == NULL) {
      if (instance_name == NULL) {
        /* If the instance name is NULL, use the default name */
        saved_instance_name = strdup(DEFAULT_INSTANCE_NAME);
        if (saved_instance_name == NULL) {
          errno = ENOMEM;
          return -1;
        }
      } else {
        /* Instead, use the one supplied by the user */
        saved_instance_name = strdup(instance_name);
        if (saved_instance_name == NULL) {
          errno = ENOMEM;
          return -1;
        }
      }
    }
  }

  /* Create the endpoint path */
  {
    int nchars;
    const size_t size = sizeof(server_addr.sun_path) - 1;

    nchars = snprintf(server_addr.sun_path, size, SOCK_DIR "/cpcd/%s/ctrl.cpcd.sock", saved_instance_name);

    /* Make sure the path fitted entirely in the struct's static buffer */
    if (nchars < 0 || (size_t) nchars >= size) {
      errno = ERANGE;
      return -1;
    }
  }

  signal(SIGUSR1, SIGUSR1_handler);

  if (handle == NULL) {
    errno = EINVAL;
    return -1;
  }

  // Check if control socket exists
  if ( access(server_addr.sun_path, F_OK) != 0 ) {
    trace_lib("access() : %s doesn't exist. The the daemon is not started or the reset sequence is not done or the secondary is not responsive.", server_addr.sun_path);
    return -1;
  }

  lib_handle = malloc(sizeof(sli_cpc_handle_t));
  if (lib_handle == NULL) {
    errno = ENOMEM;
    trace_lib("malloc()");
    return -1;
  }

  lib_handle->ctrl_sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (!lib_handle->ctrl_sock_fd) {
    trace_lib("socket()");
    free(lib_handle);
    return -1;
  }

  if (connect(lib_handle->ctrl_sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
    trace_lib("connect() : could not connect to %s. Either the process does not have the correct permissions or the secondary is not responsive.", server_addr.sun_path);
    free(lib_handle);
    return -1;
  }

  // Set ctrl socket timeout
  struct timeval timeout;
  timeout.tv_sec = CTRL_SOCKET_TIMEOUT_SEC;
  timeout.tv_usec = 0;

  if (setsockopt(lib_handle->ctrl_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0) {
    trace_lib("setsockopt()");
    free(lib_handle);
    return -1;
  }

  ret = set_pid(lib_handle);
  if (ret < 0) {
    trace_lib("failed to set pid");
    free(lib_handle);
    return -1;
  }

  ret = get_max_write(lib_handle);
  if (ret < 0) {
    trace_lib("failed to get max_write_size");
    free(lib_handle);
    return -1;
  }

  lib_handle->max_write_size = (size_t)ret;

  if (!check_version(lib_handle)) {
    trace_lib("failed to match library version with the daemon");
    free(lib_handle);
    return -1;
  }

  handle->ptr = (void *)lib_handle;
  trace_lib("CPC Lib initialized");
  return 0;
}

int cpc_restart(cpc_handle_t *handle)
{
  int ret;
  sli_cpc_handle_t *lib_handle;

  if (handle->ptr ==  NULL) {
    errno = EINVAL;
    return -1;
  }

  lib_handle = (sli_cpc_handle_t *)handle->ptr;

  ret = close(lib_handle->ctrl_sock_fd);
  if (ret != 0) {
    errno = EINVAL;
    return -1;
  }

  free(lib_handle);

  handle->ptr = NULL;

  //Init the lib again with the same parameters as the first time.
  size_t i;
  for (i = 0; i < 5; i++) {
    sleep(1);
    ret = cpc_init(handle, saved_instance_name, saved_enable_tracing, saved_reset_callback);
    if (ret == 0) {
      break;
    }
  }

  return ret;
}

/***************************************************************************/ /**
 * Connect to the socket corresponding to the provided endpoint ID.
 * The function will also allocate the memory for the endpoint structure and assign it to the provided pointer.
 * This endpoint structure must then be used for further calls to the libcpc.
 ******************************************************************************/
int cpc_open_endpoint(cpc_handle_t handle, cpc_endpoint_t *endpoint, uint8_t id, uint8_t tx_window_size)
{
  ssize_t bytes_read, bytes_written;
  sli_cpc_handle_t *lib_handle;
  cpcd_exchange_buffer_t *open_query;
  bool can_open = false;
  const size_t open_query_len = sizeof(cpcd_exchange_buffer_t) + sizeof(bool);
  sli_cpc_endpoint_t *ep;
  struct sockaddr_un ep_addr;

  trace_lib("Opening EP #%d", id);

  /* Clear struct for portability */
  memset(&ep_addr, 0, sizeof(ep_addr));

  ep_addr.sun_family = AF_UNIX;

  /* Create the endpoint socket path */
  {
    int nchars;
    const size_t size = sizeof(ep_addr.sun_path) - 1;

    nchars = snprintf(ep_addr.sun_path, size, SOCK_DIR "/cpcd/%s/ep%d.cpcd.sock", saved_instance_name, id);

    /* Make sure the path fitted entirely in the struct sockaddr_un's static buffer */
    if (nchars < 0 || (size_t) nchars >= size) {
      errno = ERANGE;
      return -1;
    }
  }

  // Only tx window of 1 is supported at the moment
  if (tx_window_size != 1) {
    errno = EINVAL;
    return -1;
  }

  if (id == 0 || endpoint == NULL || handle.ptr == NULL) {
    errno = EINVAL;
    return -1;
  }

  lib_handle = (sli_cpc_handle_t *)handle.ptr;

  ep = malloc(sizeof(sli_cpc_endpoint_t));

  if (ep == NULL) {
    errno = ENOMEM;
    return -1;
  }

  ep->id = id;
  ep->lib_handle = lib_handle;

  ep->sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (!ep->sock_fd) {
    trace_lib_error("socket()");
    free(ep);
    return -1;
  }

  open_query = (cpcd_exchange_buffer_t*) malloc(open_query_len);
  if (open_query == NULL) {
    trace_lib_error("malloc()");
    free(ep);
    return -1;
  }

  open_query->type = EXCHANGE_OPEN_ENDPOINT_QUERY;
  open_query->endpoint_number = id;
  *(bool*)(open_query->payload) = false;

  trace_lib("open endpoint, requesting open");
  bytes_written = send(lib_handle->ctrl_sock_fd, open_query, open_query_len, 0);
  if (bytes_written < (ssize_t)open_query_len) {
    trace_lib_error("write()");
    free(open_query);
    free(ep);
    return -1;
  }
  trace_lib("open endpoint, wrote %zd bytes", bytes_written);

  trace_lib("open endpoint, waiting for open request reply");
  bytes_read = recv(lib_handle->ctrl_sock_fd, open_query, open_query_len, 0);
  if (bytes_read != (ssize_t)open_query_len) {
    trace_lib_error("open endpoint failed to open request recv(), received %d bytes. Errno:", bytes_read);
    free(open_query);
    free(ep);
    return -1;
  }

  trace_lib("open endpoint received %d bytes", bytes_read);

  memcpy(&can_open, open_query->payload, sizeof(bool));

  if (can_open == false) {
    if (id == SL_CPC_ENDPOINT_SECURITY) {
      trace_lib_error("open endpoint, cannot open security endpoint as a client");
      errno = EPERM;
    } else {
      trace_lib_error("open endpoint, endpoint on secondary is not opened");
      errno = EAGAIN;
    }
    free(open_query);
    free(ep);
    return -1;
  }

  if (connect(ep->sock_fd, (struct sockaddr *)&ep_addr, sizeof(ep_addr)) < 0) {
    trace_lib_error("connect()");
    free(open_query);
    free(ep);
    return -1;
  }

  trace_lib("open endpoint, connected, waiting for server ack");
  bytes_read = recv(ep->sock_fd, open_query, open_query_len, 0);
  if (bytes_read != sizeof(cpcd_exchange_buffer_t) || open_query->type != EXCHANGE_OPEN_ENDPOINT_QUERY) {
    trace_lib_error("open endpoint open request ack recv()");
    free(open_query);
    free(ep);
    return -1;
  }

  int ep_socket_size = DEFAULT_ENDPOINT_SOCKET_SIZE;
  if (setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, &ep_socket_size, sizeof(int)) != 0) {
    trace_lib_error("open endpoint setsockopt()");
    free(open_query);
    free(ep);
    return -1;
  }

  trace_lib("Opened EP #%d", ep->id);
  endpoint->ptr = (void *)ep;

  free(open_query);

  return ep->sock_fd;
}

/***************************************************************************/ /**
 * Close the socket connection to the endpoint.
 * This function will also free the memory used to allocate the endpoint structure.
 ******************************************************************************/
int cpc_close_endpoint(cpc_endpoint_t *endpoint)
{
  sli_cpc_endpoint_t *ep;
  ssize_t bytes_written;
  ssize_t bytes_read;
  cpcd_exchange_buffer_t close_query;
  size_t close_query_len = sizeof(cpcd_exchange_buffer_t);
  sli_cpc_handle_t *lib_handle;

  if (endpoint == NULL) {
    errno = EINVAL;
    trace_lib_error("cpc_close_endpoint()");
    return -1;
  }

  ep = (sli_cpc_endpoint_t *)endpoint->ptr;

  if (ep == NULL) {
    errno = EINVAL;
    trace_lib_error("cpc_close_endpoint()");
    return -1;
  }

  trace_lib("Closing EP #%d", ep->id);

  if (close(ep->sock_fd) < 0) {
    trace_lib_error("close()");
    return -1;
  }

  lib_handle = ep->lib_handle;

  close_query.type = EXCHANGE_CLOSE_ENDPOINT_QUERY;
  close_query.endpoint_number = ep->id;

  trace_lib("Sending close request EP #%d", ep->id);
  bytes_written = send(lib_handle->ctrl_sock_fd, &close_query, close_query_len, 0);
  if (bytes_written < 0 || (size_t)bytes_written < close_query_len) {
    trace_lib_error("Close endpoint request fail");
    return -1;
  }

  trace_lib("Waiting for request reply on EP #%d", ep->id);
  bytes_read = recv(lib_handle->ctrl_sock_fd, &close_query, close_query_len, 0);
  if (bytes_read != (ssize_t)close_query_len) {
    trace_lib_error("Close request recv()");
    return -1;
  }

  free(ep);
  endpoint->ptr = NULL;

  return 0;
}

/***************************************************************************/ /**
 * Attempts to read up to count bytes from  from a previously opened endpoint socket.
 * Once data is received it will be copied to the user-provided buffer.
 * The lifecycle of this buffer is handled by the user.
 * The buffer must be at least 4087 bytes long to ensure a complete packet reception.
 * Count must be at least 4087.
 *
 * By default the cpc_read function will block indefinitely.
 * A timeout can be configured with cpc_set_option.
 ******************************************************************************/
ssize_t cpc_read_endpoint(cpc_endpoint_t endpoint, void *buffer, size_t count, cpc_read_flags_t flags)
{
  int sock_flags = 0;
  ssize_t datagram_length;
  sli_cpc_endpoint_t *ep;
  ssize_t bytes_read;

  if (buffer == NULL || count < SL_CPC_READ_MINIMUM_SIZE || endpoint.ptr == NULL) {
    errno = EINVAL;
    trace_lib_error("cpc_read_endpoint()");
    return -1;
  }

  ep = (sli_cpc_endpoint_t *)endpoint.ptr;

  trace_lib("Reading on EP #%d", ep->id);

  if (flags & SL_CPC_FLAG_NON_BLOCK) {
    sock_flags |= MSG_DONTWAIT;
  }

  datagram_length = recv(ep->sock_fd, buffer, ep->lib_handle->max_write_size, sock_flags | MSG_PEEK);
  if (datagram_length == 0) {
    trace_lib_error("recv(), datagram_length is zero bytes");
    return -1;
  } else if (datagram_length < 0) {
    if (errno != EAGAIN) {
      trace_lib_error("recv() could not peek message");
    }
    return -1;
  } else if ((size_t)datagram_length > count) {
    errno = ENOBUFS;
    return -1;
  }

  bytes_read = recv(ep->sock_fd, buffer, count, sock_flags);
  if (bytes_read == 0) {
    trace_lib_error("recv(), got zero bytes");
    return -1;
  } else if (bytes_read < 0) {
    if (errno != EAGAIN) {
      trace_lib_error("recv()");
    }
    return -1;
  }

  trace_lib("Read on EP #%d", ep->id);

  (void)flags;
  return bytes_read;
}

/***************************************************************************/ /**
 * Write data to a previously opened endpoint socket.
 * The user provides the data and the associated data length.
 ******************************************************************************/
ssize_t cpc_write_endpoint(cpc_endpoint_t endpoint, const void *data, size_t data_length, cpc_write_flags_t flags)
{
  int sock_flags = 0;
  sli_cpc_endpoint_t *ep;

  if (endpoint.ptr == NULL || data == NULL || data_length == 0) {
    errno = EINVAL;
    trace_lib_error("cpc_write_endpoint()");
    return -1;
  }

  ep = (sli_cpc_endpoint_t *)endpoint.ptr;

  if (data_length > ep->lib_handle->max_write_size) {
    errno = EINVAL;
    trace_lib_error("payload too large cpc_write_endpoint()");
    return -1;
  }

  trace_lib("Writing to EP #%d", ep->id);

  if (flags & SL_CPC_FLAG_NON_BLOCK) {
    sock_flags |= MSG_DONTWAIT;
  }

  ssize_t bytes_written = send(ep->sock_fd, data, data_length, sock_flags);
  if (bytes_written <= 0) {
    trace_lib_error("write()");
    return -1;
  }

  /*
   * The socket type between the library and the daemon are of type
   * SOCK_SEQPACKET. Unlike stream sockets, it is technically impossible
   * for DGRAM or SEQPACKET to do partial writes. The man page is ambiguous
   * about the return value in the our case, but research showed that it should
   * never happens. If it did happen, we would be in big problems because we would
   * put burden on ourself to be able to deal with partially sent messages.
   */
  assert((size_t)bytes_written == data_length);

  (void)flags;
  return bytes_written;
}

/***************************************************************************/ /**
 * Obtain the state of an endpoint via the daemon control socket.
 ******************************************************************************/
int cpc_get_endpoint_state(cpc_handle_t handle, uint8_t id, cpc_endpoint_state_t *state)
{
  sli_cpc_handle_t *lib_handle;
  cpcd_exchange_buffer_t *request_buffer;
  size_t request_buffer_len = sizeof(cpcd_exchange_buffer_t) + sizeof(cpc_endpoint_state_t);

  struct sockaddr_un server_addr;
  server_addr.sun_family = AF_UNIX;
  strncpy(server_addr.sun_path, SOCK_DIR "/ctrl.cpcd.sock", sizeof(server_addr.sun_path) - 1);

  if (state == NULL || handle.ptr == NULL || id == 0) {
    errno = EINVAL;
    return -1;
  }

  lib_handle = (sli_cpc_handle_t *)handle.ptr;

  request_buffer = malloc(request_buffer_len);
  if (request_buffer == NULL) {
    trace_lib_error("malloc()");
    errno = ENOMEM;
    return -1;
  }

  request_buffer->type = EXCHANGE_ENDPOINT_STATUS_QUERY;
  request_buffer->endpoint_number = id;
  memset(request_buffer->payload, 0, sizeof(cpc_endpoint_state_t));

  trace_lib("Get Endpoint state, writing");
  ssize_t bytes_written = send(lib_handle->ctrl_sock_fd, request_buffer, request_buffer_len, 0);
  if (bytes_written <= 0) {
    trace_lib_error("write()");
    free(request_buffer);
    return -1;
  }

  trace_lib("Get Endpoint state, reading");
  ssize_t bytes_read = recv(lib_handle->ctrl_sock_fd, request_buffer, request_buffer_len, 0);
  if (bytes_read < 0) {
    trace_lib_error("read()");
    free(request_buffer);
    return -1;
  }

  memcpy(state, request_buffer->payload, sizeof(cpc_endpoint_state_t));
  free(request_buffer);

  return 0;
}

/***************************************************************************/ /**
 * Configure an endpoint with a specified option
 ******************************************************************************/
int cpc_set_endpoint_option(cpc_endpoint_t endpoint, cpc_option_t option, const void *optval, size_t optlen)
{
  int ret;
  sli_cpc_endpoint_t *ep;

  if (option == CPC_OPTION_NONE || endpoint.ptr == NULL || optval == NULL) {
    errno = EINVAL;
    return -1;
  }

  ep = (sli_cpc_endpoint_t *)endpoint.ptr;

  if (option == CPC_OPTION_RX_TIMEOUT) {
    if (optlen != sizeof(struct timeval)) {
      errno = EINVAL;
      return -1;
    }
    ret = setsockopt(ep->sock_fd, SOL_SOCKET, SO_RCVTIMEO, optval, (socklen_t)optlen);
    if (ret < 0) {
      trace_lib_error("setsockopt()");
      return -1;
    }
  } else if (option == CPC_OPTION_TX_TIMEOUT) {
    if (optlen != sizeof(struct timeval)) {
      errno = EINVAL;
      return -1;
    }
    ret = setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDTIMEO, optval, (socklen_t)optlen);
    if (ret < 0) {
      trace_lib("error cpc_set_endpoint_option setsockopt()");
      return -1;
    }
  } else if (option == CPC_OPTION_BLOCKING) {
    if (optlen != sizeof(bool)) {
      errno = EINVAL;
      return -1;
    }

    int flags = fcntl(ep->sock_fd, F_GETFL);
    if (flags < 0) {
      trace_lib_error("fnctl()");
      return -1;
    }

    if (*(bool*)optval == true) {
      flags &= ~O_NONBLOCK;
    } else {
      flags |= O_NONBLOCK;
    }

    ret = fcntl(ep->sock_fd, F_SETFL, flags);
    if (ret < 0) {
      trace_lib_error("fnctl()");
      return -1;
    }
  } else if (option == CPC_OPTION_SOCKET_SIZE) {
    if (optlen != sizeof(int)) {
      errno = EINVAL;
      return -1;
    }

    if (setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, optval, (socklen_t)optlen) != 0) {
      trace_lib_error("setsockopt()");
      return -1;
    }
  } else {
    return -1;
  }

  return 0;
}

/***************************************************************************/ /**
 * Obtain the option configured for a specified endpoint
 ******************************************************************************/
int cpc_get_endpoint_option(cpc_endpoint_t endpoint, cpc_option_t option, void *optval, size_t *optlen)
{
  int ret;
  sli_cpc_endpoint_t *ep;
  socklen_t socklen = (socklen_t)*optlen;

  if (option == CPC_OPTION_NONE || endpoint.ptr == NULL || optval == NULL || optlen == NULL) {
    errno = EINVAL;
    return -1;
  }

  ep = (sli_cpc_endpoint_t *)endpoint.ptr;

  if (option == CPC_OPTION_RX_TIMEOUT) {
    ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_RCVTIMEO, optval, &socklen);
    *optlen = (size_t)socklen;
    if (ret < 0) {
      trace_lib_error("getsockopt()");
      return -1;
    }
  } else if (option == CPC_OPTION_RX_TIMEOUT) {
    ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_RCVTIMEO, optval, &socklen);
    *optlen = (size_t)socklen;
    if (ret < 0) {
      trace_lib("error cpc_get_endpoint_option getsockopt()");
      return -1;
    }
  } else if (option == CPC_OPTION_TX_TIMEOUT) {
    ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDTIMEO, optval, &socklen);
    *optlen = (size_t)socklen;
    if (ret < 0) {
      trace_lib("error cpc_get_endpoint_option getsockopt()");
      return -1;
    }
  } else if (option == CPC_OPTION_BLOCKING) {
    *optlen = sizeof(bool);

    int flags = fcntl(ep->sock_fd, F_GETFL);
    if (flags < 0) {
      trace_lib_error("fnctl()");
      return -1;
    }

    if (flags & O_NONBLOCK) {
      *(bool *)optval = false;
    } else {
      *(bool *)optval = true;
    }
  } else if (option == CPC_OPTION_SOCKET_SIZE) {
    *optlen = sizeof(int);

    ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, optval, &socklen);
    *optlen = (size_t)socklen;
    if (ret < 0) {
      trace_lib_error("getsockopt()");
      return -1;
    }
  } else if (option == CPC_OPTION_MAX_WRITE_SIZE) {
    *optlen = sizeof(size_t);
    memcpy(optval, &ep->lib_handle->max_write_size, sizeof(ep->lib_handle->max_write_size));
  } else {
    return -1;
  }

  return 0;
}
