/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Server
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
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "cpcd/config.h"
#include "cpcd/event.h"
#include "cpcd/exchange.h"
#include "cpcd/logging.h"
#include "cpcd/security.h"
#include "cpcd/server_core.h"
#include "cpcd/sl_slist.h"
#include "cpcd/utils.h"

#include "server_core/server/server.h"
#include "server_core/server/server_internal.h"
#include "server_core/server/server_ready_sync.h"
#include "server_core/system_endpoint/system.h"
#include "server_core/epoll/epoll.h"
#include "server_core/core/core.h"
#include "sl_cpc.h"
#include "version.h"

/*******************************************************************************
 ***************************  LOCAL DECLARATIONS   *****************************
 ******************************************************************************/

typedef struct {
  sl_slist_node_t node;
  uint8_t endpoint_id;
  uint8_t tx_window_size;
  int fd_ctrl_data_socket;
  bool in_progress;
} pending_connection_list_item_t;

typedef struct {
  sl_slist_node_t node;
  epoll_private_data_t data_socket_epoll_private_data;
  pid_t pid;
} ctrl_socket_private_data_list_item_t;

typedef struct {
  sl_slist_node_t node;
  epoll_private_data_t reset_socket_epoll_private_data;
} reset_socket_private_data_list_item_t;

typedef struct {
  sl_slist_node_t node;
  epoll_private_data_t event_socket_epoll_private_data;
} event_socket_private_data_list_item_t;

typedef struct {
  sl_slist_node_t node;
  epoll_private_data_t data_socket_epoll_private_data;
  int conn_data_fd;
  int conn_ctrl_fd;
} data_connection_t;

typedef struct {
  uint32_t open_data_connections;
  uint32_t open_event_connections;
  uint32_t pending_close;
  epoll_private_data_t event_connection_socket_epoll_private_data;
  epoll_private_data_t connection_socket_epoll_private_data;
  sl_slist_node_t* event_data_socket_epoll_private_data;
  sl_slist_node_t *data_connections;
  sl_slist_node_t *closed_data_connections;
  uint8_t tx_window_size;
  int connecting_data_socket_fd;
} endpoint_control_block_t;

/*******************************************************************************
 ***************************  GLOBAL VARIABLES   *******************************
 ******************************************************************************/

endpoint_control_block_t endpoints[256];

/* List to keep track of libraries that are blocking on the cpc_open call */
static sl_slist_node_t *pending_connections;

/* List to keep track of every connected library instance over the control socket */
static sl_slist_node_t *ctrl_connections;

/* List to keep track of every connected library instance over the reset socket */
static sl_slist_node_t *reset_connections;

/*******************************************************************************
 ***************************  LOCAL VARIABLES   ********************************
 ******************************************************************************/

static int fd_socket_ctrl;
static int fd_socket_reset;

/*******************************************************************************
 **************************   LOCAL FUNCTIONS   ********************************
 ******************************************************************************/

#if !defined(UNIT_TESTING)
static void server_process_epoll_fd_timeout_noop(epoll_private_data_t *private_data);
#endif

static void server_process_epoll_fd_ctrl_connection_socket(epoll_private_data_t *private_data);
static void server_process_epoll_fd_ctrl_data_socket(epoll_private_data_t *private_data);
static void server_process_epoll_fd_event_connection_socket(epoll_private_data_t *private_data);
static void server_process_epoll_fd_event_data_socket(epoll_private_data_t *private_data);
static void server_process_epoll_fd_ep_connection_socket(epoll_private_data_t *private_data);
static void server_process_epoll_fd_ep_data_socket(epoll_private_data_t *private_data);
static void server_process_epoll_fd_reset_connection_socket(epoll_private_data_t *private_data);
static void server_process_epoll_fd_reset_data_socket(epoll_private_data_t *private_data);

static cpc_endpoint_state_t server_convert_endpoint_state_internal_to_public(sli_cpc_endpoint_state_t internal_ep_state);
static void server_set_tx_window_size(uint8_t endpoint_id, uint8_t tx_window_size);
static void server_open_endpoint_event_socket(uint8_t endpoint_number);
static void server_handle_client_disconnected(uint8_t endpoint_number);
static void server_handle_client_closed_ep_connection(int fd_data_socket, uint8_t endpoint_number);
static bool server_handle_client_closed_ep_notify_close(uint8_t endpoint_number, data_connection_t *conn);
static void server_handle_client_closed_ctrl_connection(int fd_data_socket);
static void server_handle_client_closed_event_connection(int fd_data_socket, uint8_t endpoint_number);
static void server_handle_client_closed_reset_connection(int fd_reset_data_socket);
static bool server_ep_remove_closed_connection(uint8_t endpoint_number, int conn_data_fd);
static void server_ep_mark_close_pending(uint8_t endpoint_number, int fd_data_socket, int fd_ctrl_socket);
static int server_pull_data_from_data_socket(int fd_data_socket, uint8_t** buffer_ptr, size_t* buffer_len_ptr);

static void server_open_endpoint(uint8_t endpoint_number);
static void server_finalize_open_endpoint(uint8_t endpoint_id, sl_status_t status, void *server_ctx);

/*******************************************************************************
 **************************   IMPLEMENTATION    ********************************
 ******************************************************************************/
void server_init(void)
{
#if !defined(UNIT_TESTING)
  int fd_timer_noop;
#endif

  int ret;

  /* Create the control socket /tmp/cpcd/{instance_name}/ctrl.cpcd.sock and start listening for connections */
  {
    /* Create datagram socket for control */
    fd_socket_ctrl = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    FATAL_SYSCALL_ON(fd_socket_ctrl < 0);

    /* Bind socket to socket name. */
    {
      struct sockaddr_un name;

      /* Clear struct for portability */
      memset(&name, 0, sizeof(name));

      name.sun_family = AF_UNIX;

      /* Create the control socket path */
      {
        int nchars;
        const size_t size = sizeof(name.sun_path) - 1;

        nchars = snprintf(name.sun_path, size, "%s/cpcd/%s/ctrl.cpcd.sock", config.socket_folder, config.instance_name);

        /* Make sure the path fitted entirely in the struct's static buffer */
        FATAL_ON(nchars < 0 || (size_t) nchars >= size);
      }

      ret = bind(fd_socket_ctrl, (const struct sockaddr *) &name, sizeof(name));
      FATAL_SYSCALL_ON(ret < 0);
    }

    /*
     * Prepare for accepting connections. The backlog size is set
     * to 5. So while one request is being processed other requests
     * can be waiting.
     */
    ret = listen(fd_socket_ctrl, 5);
    FATAL_SYSCALL_ON(ret < 0);

    /* Init the linked list of connected instances of the library to /run/cpc/ctrl.cpcd.sock (to empty) */
    sl_slist_init(&ctrl_connections);

    /* Init the linked list of pending client connections */
    sl_slist_init(&pending_connections);
  }

  /* Create the reset socket /tmp/cpcd/{instance_name}/reset.cpcd.sock and start listening for connections */
  {
    /* Create datagram socket for reset */
    fd_socket_reset = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    FATAL_SYSCALL_ON(fd_socket_reset < 0);

    /* Bind socket to socket name. */
    {
      struct sockaddr_un name;

      /* Clear struct for portability */
      memset(&name, 0, sizeof(name));

      name.sun_family = AF_UNIX;

      /* Create the reset socket path */
      {
        int nchars;
        const size_t size = sizeof(name.sun_path) - 1;

        nchars = snprintf(name.sun_path, size, "%s/cpcd/%s/reset.cpcd.sock", config.socket_folder, config.instance_name);

        /* Make sure the path fitted entirely in the struct's static buffer */
        FATAL_ON(nchars < 0 || (size_t) nchars >= size);
      }

      ret = bind(fd_socket_reset, (const struct sockaddr *) &name, sizeof(name));
      FATAL_SYSCALL_ON(ret < 0);
    }

    /*
     * Prepare for accepting connections. The backlog size is set
     * to 5. So while one request is being processed other requests
     * can be waiting.
     */
    ret = listen(fd_socket_reset, 5);
    FATAL_SYSCALL_ON(ret < 0);

    /* Init the linked list of connected instances of the library to /run/cpc/reset.cpcd.sock (to empty) */
    sl_slist_init(&reset_connections);
  }

  /* Initialize every endpoint control block */
  {
    size_t i;

    for (i = 1; i != 256; i++) { /* dont care for ep#0 */
      endpoints[i].open_data_connections = 0;
      endpoints[i].open_event_connections = 0;
      endpoints[i].pending_close = 0;
      endpoints[i].connection_socket_epoll_private_data.endpoint_number = (uint8_t)i;
      endpoints[i].connection_socket_epoll_private_data.file_descriptor = -1;
      endpoints[i].event_connection_socket_epoll_private_data.file_descriptor = -1;
      endpoints[i].connecting_data_socket_fd = -1;

      sl_slist_init(&endpoints[i].event_data_socket_epoll_private_data);
      sl_slist_init(&endpoints[i].data_connections);
      sl_slist_init(&endpoints[i].closed_data_connections);
    }
  }

  /* Setup no-op timer. Trig in 1 sec, and every 1 sec after that */
  if (config.use_noop_keep_alive) {
#if !defined(UNIT_TESTING)
    const struct itimerspec timeout = { .it_interval = { .tv_sec = 5, .tv_nsec = 0 },
                                        .it_value    = { .tv_sec = 5, .tv_nsec = 0 } };

    /* Periodic no-op timer  */
    {
      fd_timer_noop = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
      FATAL_SYSCALL_ON(fd_timer_noop < 0);

      ret = timerfd_settime(fd_timer_noop,
                            0,
                            &timeout,
                            NULL);
      FATAL_SYSCALL_ON(ret < 0);
    }

    /* Setup the timerfd for noop polling */
    {
      static epoll_private_data_t private_data;

      private_data.callback = server_process_epoll_fd_timeout_noop;
      private_data.file_descriptor = fd_timer_noop;
      private_data.endpoint_number = 0; /* Irrelevant here */

      epoll_register(&private_data);
    }
#endif
  }

  /* Setup epoll */
  {
    /* Setup the control socket */
    {
      static epoll_private_data_t private_data;

      private_data.callback = server_process_epoll_fd_ctrl_connection_socket;
      private_data.file_descriptor = fd_socket_ctrl;
      private_data.endpoint_number = 0; /* Irrelevant here */

      epoll_register(&private_data);
    }

    /* Setup the reset socket */
    {
      static epoll_private_data_t private_data;

      private_data.callback = server_process_epoll_fd_reset_connection_socket;
      private_data.file_descriptor = fd_socket_reset;
      private_data.endpoint_number = 0; /* Irrelevant here */

      epoll_register(&private_data);
    }

    /* per-endpoint connection sockets are dynamically created [and added to epoll set] when endpoints are opened */

    /* per-endpoint event sockets are dynamically created [and added to epoll set] when endpoints are opened */

    /* per-endpoint data sockets are dynamically created [and added to epoll set] when instances of library are connecting to an endpoint */
  }

  /* The server up and running, unblock possible threads waiting for it. */
  server_ready_post();
}

static void server_process_epoll_fd_event_connection_socket(epoll_private_data_t *private_data)
{
  int new_data_socket, flags;
  int fd_connection_socket = private_data->file_descriptor;
  uint8_t endpoint_number = private_data->endpoint_number;

  /* Sanity checks */
  {
    /* We don't deal with system endpoint here*/
    BUG_ON(endpoint_number == 0);

    /* Make sure the connection socket exists */
    BUG_ON(endpoints[endpoint_number].event_connection_socket_epoll_private_data.file_descriptor == -1);
  }

  /* Accept the new connection for that endpoint */
  new_data_socket = accept(fd_connection_socket, NULL, NULL);
  FATAL_SYSCALL_ON(new_data_socket < 0);

  /* Set socket as non-blocking */
  flags = fcntl(new_data_socket, F_GETFL, NULL);

  if (flags < 0) {
    FATAL("fcntl F_GETFL failed.%s", strerror(errno));
  }

  flags |= O_NONBLOCK;

  if (fcntl(new_data_socket, F_SETFL, flags) < 0) {
    FATAL("fcntl F_SETFL failed.%s", strerror(errno));
  }

  /* Add the new data socket in the list of data sockets for that endpoint */
  {
    event_socket_private_data_list_item_t* new_item;

    /* Allocate resources for this new connection */
    {
      new_item = (event_socket_private_data_list_item_t*) zalloc(sizeof(event_socket_private_data_list_item_t));
      FATAL_ON(new_item == NULL);

      sl_slist_push(&endpoints[endpoint_number].event_data_socket_epoll_private_data, &new_item->node);
    }

    /* Register this new connection's socket to epoll set */
    {
      epoll_private_data_t* private_data = &new_item->event_socket_epoll_private_data;

      private_data->callback = server_process_epoll_fd_event_data_socket;
      private_data->endpoint_number = endpoint_number;
      private_data->file_descriptor = new_data_socket;

      epoll_register(private_data);
    }
  }

  endpoints[endpoint_number].open_event_connections++;
  PRINT_INFO("Endpoint event socket #%d: Client connected (%d). %d connections", endpoint_number, new_data_socket, endpoints[endpoint_number].open_event_connections);
}

static void server_process_epoll_fd_ctrl_connection_socket(epoll_private_data_t *private_data)
{
  (void) private_data;
  int new_data_socket;
  int flags;
  int ret;

  /* Accept the new ctrl connection for that client */
  new_data_socket = accept(fd_socket_ctrl, NULL, NULL);
  FATAL_SYSCALL_ON(new_data_socket < 0);

  /* Set socket as non-blocking */
  flags = fcntl(new_data_socket, F_GETFL, NULL);
  FATAL_SYSCALL_ON(flags < 0);
  ret = fcntl(new_data_socket, F_SETFL, flags | O_NONBLOCK);
  FATAL_SYSCALL_ON(ret < 0);

  /* Add the new data socket in the list of data sockets for ctrl */
  {
    ctrl_socket_private_data_list_item_t* new_item;

    /* Allocate resources for this new connection */
    new_item = zalloc(sizeof(*new_item));
    new_item->pid = -1;

    /* Register this new data socket to epoll set */
    {
      epoll_private_data_t* private_data = &new_item->data_socket_epoll_private_data;

      private_data->callback = server_process_epoll_fd_ctrl_data_socket;
      private_data->endpoint_number = 0; /* Irrelevent information in the case of ctrl data sockets */
      private_data->file_descriptor = new_data_socket;

      epoll_register(private_data);
    }

    /* Finally, add this new socket item to the list */
    sl_slist_push(&ctrl_connections, &new_item->node);
  }
}

static void server_process_epoll_fd_reset_connection_socket(epoll_private_data_t *private_data)
{
  (void) private_data;
  int reset_data_socket;
  int flags;
  int ret;

  /* Accept the new reset connection for that client */
  reset_data_socket = accept(fd_socket_reset, NULL, NULL);
  FATAL_SYSCALL_ON(reset_data_socket < 0);

  /* Set socket as non-blocking */
  flags = fcntl(reset_data_socket, F_GETFL, NULL);
  FATAL_SYSCALL_ON(flags < 0);
  ret = fcntl(reset_data_socket, F_SETFL, flags | O_NONBLOCK);
  FATAL_SYSCALL_ON(ret < 0);

  /* Add the new client socket in the list of reset sockets */
  {
    reset_socket_private_data_list_item_t* new_item;

    /* Allocate resources for this new connection */
    new_item = zalloc(sizeof(*new_item));

    /* Register this new reset data socket to epoll set */
    {
      epoll_private_data_t* private_data = &new_item->reset_socket_epoll_private_data;

      private_data->callback = server_process_epoll_fd_reset_data_socket;
      private_data->endpoint_number = 0; /* Irrelevent information in the case of reset data sockets */
      private_data->file_descriptor = reset_data_socket;

      epoll_register(private_data);
    }

    /* Finally, add this new socket item to the list */
    sl_slist_push(&reset_connections, &new_item->node);
  }
}

static void server_process_epoll_fd_event_data_socket(epoll_private_data_t *private_data)
{
  int fd_event_data_socket = private_data->file_descriptor;
  uint8_t* buffer;
  size_t buffer_len;
  cpcd_exchange_buffer_t *interface_buffer;
  int ret;
  uint8_t endpoint_number = private_data->endpoint_number;

  /* Sanity checks */
  {
    /* We don't deal with system endpoint here*/
    BUG_ON(endpoint_number == 0);

    /* Make sure the connection socket exists */
    BUG_ON(endpoints[endpoint_number].event_connection_socket_epoll_private_data.file_descriptor == -1);
  }

  /* Check if the event is about the client closing the connection */
  {
    int length;

    ret = ioctl(fd_event_data_socket, FIONREAD, &length);
    FATAL_SYSCALL_ON(ret < 0);

    if (length == 0) {
      server_handle_client_closed_event_connection(fd_event_data_socket, endpoint_number);
      return;
    }
  }

  /* Retrieve the payload from the endpoint data connection */
  ret = server_pull_data_from_data_socket(fd_event_data_socket, &buffer, &buffer_len);
  FATAL_ON(ret != 0);

  FATAL_ON(buffer_len < sizeof(cpcd_exchange_buffer_t));
  interface_buffer = (cpcd_exchange_buffer_t *)buffer;

  switch (interface_buffer->type) {
    default:
      break;
  }

  free(buffer);
}

static cpc_endpoint_state_t server_convert_endpoint_state_internal_to_public(sli_cpc_endpoint_state_t internal_ep_state)
{
  switch (internal_ep_state) {
    case SLI_CPC_STATE_OPEN:
    case SLI_CPC_STATE_CLOSED:
    case SLI_CPC_STATE_CONNECTING:
    case SLI_CPC_STATE_DISCONNECTED:
    case SLI_CPC_STATE_FREED:
      return SL_CPC_STATE_CLOSED;
    case SLI_CPC_STATE_SHUTTING_DOWN:
    case SLI_CPC_STATE_SHUTDOWN:
    case SLI_CPC_STATE_REMOTE_SHUTDOWN:
    case SLI_CPC_STATE_CLOSING:
      return SL_CPC_STATE_CLOSING;
    case SLI_CPC_STATE_CONNECTED:
      return SL_CPC_STATE_OPEN;
    case SLI_CPC_STATE_ERROR_DESTINATION_UNREACHABLE:
      return SL_CPC_STATE_ERROR_DESTINATION_UNREACHABLE;
    case SLI_CPC_STATE_ERROR_SECURITY_INCIDENT:
      return SL_CPC_STATE_ERROR_SECURITY_INCIDENT;
    case SLI_CPC_STATE_ERROR_FAULT:
      return SL_CPC_STATE_ERROR_FAULT;
    default:
      BUG("Unhandled internal state %d", internal_ep_state);
  }
}

static void server_process_epoll_fd_ctrl_data_socket(epoll_private_data_t *private_data)
{
  int fd_ctrl_data_socket = private_data->file_descriptor;
  uint8_t* buffer;
  size_t buffer_len;
  cpcd_exchange_buffer_t *interface_buffer;
  int ret;

  /* Check if the event is about the client closing the connection */
  {
    int length;

    ret = ioctl(fd_ctrl_data_socket, FIONREAD, &length);
    FATAL_SYSCALL_ON(ret < 0);

    if (length == 0) {
      server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
      return;
    }
  }

  /* Retrieve the payload from the endpoint data connection */
  ret = server_pull_data_from_data_socket(fd_ctrl_data_socket, &buffer, &buffer_len);
  FATAL_ON(ret != 0);

  FATAL_ON(buffer_len < sizeof(cpcd_exchange_buffer_t));
  interface_buffer = (cpcd_exchange_buffer_t *)buffer;

  switch (interface_buffer->type) {
    case EXCHANGE_ENDPOINT_STATUS_QUERY:
      /* Client requested an endpoint status */
    {
      sli_cpc_endpoint_state_t internal_ep_state;
      cpc_endpoint_state_t public_ep_state;

      TRACE_SERVER("Received an endpoint status query");

      BUG_ON(buffer_len != sizeof(cpcd_exchange_buffer_t) + sizeof(cpc_endpoint_state_t));

      internal_ep_state = core_get_endpoint_state(interface_buffer->endpoint_number);
      public_ep_state = server_convert_endpoint_state_internal_to_public(internal_ep_state);

      memcpy(interface_buffer->payload, &public_ep_state, sizeof(cpc_endpoint_state_t));

      ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

      if (ret < 0 && errno == EPIPE) {
        server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
      } else {
        FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
        FATAL_ON((size_t)ret != sizeof(cpcd_exchange_buffer_t) + sizeof(cpc_endpoint_state_t));
      }
    }
    break;

    case EXCHANGE_MAX_WRITE_SIZE_QUERY:
      /* Client requested maximum write size */
    {
      uint32_t rx_capability;

      TRACE_SERVER("Received an maximum write size query");

      BUG_ON(buffer_len != sizeof(cpcd_exchange_buffer_t) + sizeof(uint32_t));

      rx_capability = server_core_get_secondary_rx_capability();

      memcpy(interface_buffer->payload, &rx_capability, sizeof(uint32_t));

      ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

      if (ret < 0 && errno == EPIPE) {
        server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
      } else {
        FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
        FATAL_ON((size_t)ret != sizeof(cpcd_exchange_buffer_t) + sizeof(uint32_t));
      }
    }
    break;

    case EXCHANGE_VERSION_QUERY:
      /* Client requested the version of the daemon*/
    {
      char* version = (char*)interface_buffer->payload;
      bool do_close_client = false;

      FATAL_ON(interface_buffer->payload == NULL);

      TRACE_SERVER("Received a version query");

      if (buffer_len != sizeof(cpcd_exchange_buffer_t) + sizeof(char) * PROJECT_MAX_VERSION_SIZE) {
        WARN("Client used invalid version buffer_len = %zu", buffer_len);
        break;
      }

      if (strnlen(version, PROJECT_MAX_VERSION_SIZE) == PROJECT_MAX_VERSION_SIZE) {
        do_close_client = true;
        WARN("Client used invalid library version, version string is invalid");
      } else if (strcmp(version, PROJECT_VER) != 0) {
        do_close_client = true;
        WARN("Client used invalid library version, (v%s) expected (v%s)", version, PROJECT_VER);
      } else {
        PRINT_INFO("New client connection using library v%s", version);
      }

      //Reuse the receive buffer to send back the response
      strncpy(version, PROJECT_VER, PROJECT_MAX_VERSION_SIZE);

      ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

      if ((ret < 0 && errno == EPIPE) || do_close_client) {
        server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
      } else {
        FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
        FATAL_ON((size_t)ret != sizeof(cpcd_exchange_buffer_t) + sizeof(char) * PROJECT_MAX_VERSION_SIZE);
      }
    }
    break;

    case EXCHANGE_SECONDARY_APP_VERSION_SIZE_QUERY:
      /* Client requested the size of the application version string */
    {
      TRACE_SERVER("Received a secondary app version size query");

      BUG_ON(buffer_len != sizeof(cpcd_exchange_buffer_t) + sizeof(uint16_t));

      uint16_t app_version_size = (uint16_t)strlen(server_core_get_secondary_app_version());
      memcpy(interface_buffer->payload, &app_version_size, sizeof(app_version_size));

      ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

      if (ret < 0 && errno == EPIPE) {
        server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
      } else {
        FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
        FATAL_ON((size_t)ret != buffer_len);
      }
    }
    break;

    case EXCHANGE_SECONDARY_APP_VERSION_STRING_QUERY:
      /* Client requested the version string of the secondary application version */
    {
      size_t app_version_size = strlen(server_core_get_secondary_app_version());

      TRACE_SERVER("Received a secondary application version string query");

      BUG_ON(buffer_len != sizeof(cpcd_exchange_buffer_t) + app_version_size);

      memcpy(interface_buffer->payload, server_core_get_secondary_app_version(), app_version_size);

      ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

      if (ret < 0 && errno == EPIPE) {
        server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
      } else {
        FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
        FATAL_ON((size_t)ret != buffer_len);
      }
    }
    break;

    case EXCHANGE_OPEN_ENDPOINT_QUERY:
      /* Client requested to open an endpoint socket*/
    {
      BUG_ON(buffer_len != sizeof(cpcd_exchange_buffer_t) + sizeof(uint8_t) + sizeof(bool));

      TRACE_SERVER("Received an open query for endpoint #%d", interface_buffer->endpoint_number);

      //Be careful when asked about opening the security endpoint...
      if (interface_buffer->endpoint_number == SL_CPC_ENDPOINT_SECURITY) {
        if (endpoints[SL_CPC_ENDPOINT_SECURITY].data_connections != NULL // Make sure only 1 client is connected (ie, the daemon' security thread)
            || config.use_encryption == false) {                                      // Make sure security is enabled
          // Reuse the same buffer to send a negative reply
          bool reply = false;
          memcpy(&(interface_buffer->payload[1]), &reply, sizeof(bool));

          ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

          if (ret < 0 && errno == EPIPE) {
            server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
          } else {
            FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
            FATAL_ON((size_t)ret != buffer_len);
          }
          break;
        }
      }

      pending_connection_list_item_t *entry;
      bool found = false;

      SL_SLIST_FOR_EACH_ENTRY(pending_connections, entry, pending_connection_list_item_t, node) {
        if (entry->endpoint_id == interface_buffer->endpoint_number
            && entry->fd_ctrl_data_socket == fd_ctrl_data_socket) {
          TRACE_SERVER("Found an existing open endpoint query, skipping this one",
                       interface_buffer->endpoint_number);
          found = true;
          break;
        }
      }

      if (!found) {
        // Add this connection to the pending connections list, we need
        // to check the secondary if the endpoint is open. This will
        // be done in the server_process_pending_connections function
        pending_connection_list_item_t *pending_connection = zalloc(sizeof(pending_connection_list_item_t));
        FATAL_ON(pending_connection == NULL);

        pending_connection->endpoint_id = interface_buffer->endpoint_number;
        pending_connection->tx_window_size = interface_buffer->payload[0];
        pending_connection->fd_ctrl_data_socket = fd_ctrl_data_socket;
        pending_connection->in_progress = false;
        sl_slist_push_back(&pending_connections, &pending_connection->node);
      }
    }
    break;

    case EXCHANGE_CLOSE_ENDPOINT_QUERY:
    {
      TRACE_SERVER("Received a endpoint close query");
      /* Endpoint was closed by secondary */
      if (endpoints[interface_buffer->endpoint_number].pending_close > 0) {
        endpoints[interface_buffer->endpoint_number].pending_close--;

        // if the query comes from the last client holding a reference to
        // that endpoint, ask the core to close the endpoint
        if (endpoints[interface_buffer->endpoint_number].pending_close == 0) {
          core_close_endpoint(interface_buffer->endpoint_number, true, false);
        }

        // Ack the close query
        ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
        if (ret < 0 && errno == EPIPE) {
          server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
        } else {
          FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
          FATAL_ON((size_t)ret != (sizeof(cpcd_exchange_buffer_t) + sizeof(int)));
          // And notify the caller
          ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
          if (ret < 0 && errno == EPIPE) {
            server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
          } else {
            FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
            FATAL_ON((size_t)ret != (sizeof(cpcd_exchange_buffer_t) + sizeof(int)));
          }
        }
      } else {
        /* Endpoint is about to be closed by a client */
        int fd_data_socket;
        bool conn_closed;

        memcpy(&fd_data_socket, interface_buffer->payload, sizeof(fd_data_socket));

        // check if the connection was already closed for file descriptor
        // `fd_data_socket`. If it is, it might be because the daemon
        // closed it because of an error for instance.
        conn_closed = server_ep_remove_closed_connection(interface_buffer->endpoint_number,
                                                         fd_data_socket);

        /* Endpoint was already closed by a client (same ctrl data socket, multiple instances of the same endpoint) */
        if (core_get_endpoint_state(interface_buffer->endpoint_number) == SLI_CPC_STATE_CLOSED
            || conn_closed) {
          // Ack the close query
          ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
          if (ret < 0 && errno == EPIPE) {
            server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
          } else {
            FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
            FATAL_ON((size_t)ret != (sizeof(cpcd_exchange_buffer_t) + sizeof(int)));
            // And notify the caller
            ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
            if (ret < 0 && errno == EPIPE) {
              server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
            } else {
              FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
              FATAL_ON((size_t)ret != (sizeof(cpcd_exchange_buffer_t) + sizeof(int)));
            }
          }
        } else {
          // The connection is still active, acknowledge the first
          // half of the query, the second half will be handled by
          // server_handle_client_closed_ep_notify_close() when
          // the endpoint connection file descriptor will be closed
          // by the user.
          server_ep_mark_close_pending(interface_buffer->endpoint_number,
                                       fd_data_socket,
                                       fd_ctrl_data_socket);

          // Ack the close query
          ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
          if (ret < 0 && errno == EPIPE) {
            server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
          } else {
            FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
            FATAL_ON((size_t)ret != (sizeof(cpcd_exchange_buffer_t) + sizeof(int)));
          }
        }
      }
    }
    break;

    case EXCHANGE_SET_PID_QUERY:
    {
      ctrl_socket_private_data_list_item_t* item;
      pid_t library_pid;

      memcpy(&library_pid, interface_buffer->payload, sizeof(library_pid));

      // Set the control socket PID
      item = container_of(private_data, ctrl_socket_private_data_list_item_t, data_socket_epoll_private_data);
      item->pid = library_pid;
    }
    break;

    case EXCHANGE_NORMAL_OPERATION_MODE_QUERY:
    {
      bool normal_operational_mode = false;
      ctrl_socket_private_data_list_item_t* item;

      TRACE_SERVER("Received a normal operation mode query");

      item = container_of(private_data, ctrl_socket_private_data_list_item_t, data_socket_epoll_private_data);

      BUG_ON(item->pid == -1);
      BUG_ON(buffer_len != sizeof(cpcd_exchange_buffer_t) + sizeof(bool));

      normal_operational_mode = config.operation_mode == MODE_NORMAL || item->pid == getpid();

      memcpy(interface_buffer->payload, &normal_operational_mode, sizeof(bool));

      ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

      if (ret < 0 && errno == EPIPE) {
        server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
      } else {
        FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
        FATAL_ON((size_t)ret != sizeof(cpcd_exchange_buffer_t) + sizeof(bool));
      }
    }
    break;

    case EXCHANGE_ENDPOINT_ENCRYPTION_QUERY:
    {
      bool ep_encryption;
      TRACE_SERVER("Received an endpoint encryption query");

      BUG_ON(buffer_len != sizeof(cpcd_exchange_buffer_t) + sizeof(bool));

      ep_encryption = core_get_endpoint_encryption(interface_buffer->endpoint_number);

      memcpy(interface_buffer->payload, &ep_encryption, sizeof(bool));

      ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

      if (ret < 0 && errno == EPIPE) {
        server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
      } else {
        FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
        FATAL_ON((size_t)ret != sizeof(cpcd_exchange_buffer_t) + sizeof(bool));
      }
    }
    break;

    case EXCHANGE_OPEN_ENDPOINT_EVENT_SOCKET_QUERY:
    {
      server_open_endpoint_event_socket(interface_buffer->endpoint_number);

      // Ack the query
      ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
      if (ret < 0 && errno == EPIPE) {
        server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
      } else {
        FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
        FATAL_ON((size_t)ret != sizeof(cpcd_exchange_buffer_t));
      }
    }
    break;

    default:
      break;
  }

  free(buffer);
}

static void server_process_epoll_fd_reset_data_socket(epoll_private_data_t *private_data)
{
  int fd_reset_data_socket = private_data->file_descriptor;
  int ret;

  /* Check if the event is about the client closing the connection */
  {
    int length;

    ret = ioctl(fd_reset_data_socket, FIONREAD, &length);
    FATAL_SYSCALL_ON(ret < 0);

    if (length == 0) {
      server_handle_client_closed_reset_connection(fd_reset_data_socket);
      return;
    }
  }
}

#if defined(ENABLE_ENCRYPTION)
static pending_connection_list_item_t* server_reorder_pending_connections(void)
{
  pending_connection_list_item_t *pending_connection;
  pending_connection = SL_SLIST_ENTRY(pending_connections, pending_connection_list_item_t, node);
  sl_cpc_security_state_t security_state = security_get_state();

  if (config.use_encryption && security_state != SECURITY_STATE_DISABLED) {
    if (security_state != SECURITY_STATE_INITIALIZED) {
      uint8_t head_endpoint_id = pending_connection->endpoint_id;

      if (head_endpoint_id != SL_CPC_ENDPOINT_SECURITY) {
        sl_slist_node_t *node;

        TRACE_SERVER("Delaying opening of endpoint #%d as security is not initialized yet",
                     head_endpoint_id);

        do {
          node = sl_slist_pop(&pending_connections);
          sl_slist_push_back(&pending_connections, node);

          pending_connection = SL_SLIST_ENTRY(pending_connections,
                                              pending_connection_list_item_t,
                                              node);
        } while (pending_connection->endpoint_id != SL_CPC_ENDPOINT_SECURITY
                 && pending_connection->endpoint_id != head_endpoint_id);

        if (pending_connection->endpoint_id == head_endpoint_id) {
          pending_connection = NULL;
        }
      }
    }
  }

  return pending_connection;
}
#endif

void server_process_pending_connections(void)
{
  pending_connection_list_item_t *pending_connection;
  pending_connection = SL_SLIST_ENTRY(pending_connections, pending_connection_list_item_t, node);

  if (pending_connection != NULL && !pending_connection->in_progress) {
    if (core_ep_is_closing(pending_connection->endpoint_id)) {
      TRACE_SERVER("Endpoint #%d is currently closing, waiting before opening", pending_connection->endpoint_id);
      return;
    }

#if defined(ENABLE_ENCRYPTION)
    pending_connection = server_reorder_pending_connections();
    if (pending_connection == NULL) {
      TRACE_SERVER("Delaying processing of pending connections, waiting on security");
      return;
    }
#endif

    if (!server_is_endpoint_open(pending_connection->endpoint_id)) {
      server_set_tx_window_size(pending_connection->endpoint_id,
                                pending_connection->tx_window_size);
    }

    pending_connection->in_progress = true;
    TRACE_SERVER("Asking core to fetch ep#%d state", pending_connection->endpoint_id);
    core_remote_ep_is_opened(pending_connection->endpoint_id,
                             server_finalize_open_endpoint,
                             pending_connection);
  }
}

/***************************************************************************//**
 * Send an acknowledge to the ctrl socket about the open endpoint query.
 ******************************************************************************/
static void system_send_open_endpoint_ack(uint8_t endpoint_id,
                                          bool can_open,
                                          pending_connection_list_item_t *connection)
{
  const size_t buffer_len = sizeof(cpcd_exchange_buffer_t) + sizeof(uint8_t) + sizeof(bool);
  cpcd_exchange_buffer_t *interface_buffer;
  uint8_t buffer[buffer_len];

  interface_buffer = (cpcd_exchange_buffer_t*)buffer;

  // populate fields related to the query
  interface_buffer->type = EXCHANGE_OPEN_ENDPOINT_QUERY;
  interface_buffer->endpoint_number = endpoint_id;
  memset(interface_buffer->payload, 0, 1);
  memcpy(&(interface_buffer->payload[1]), &can_open, sizeof(bool));

  ssize_t ret = send(connection->fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
  TRACE_SERVER("Replied to endpoint open query on ep#%d", endpoint_id);

  if (ret == -1) {
    WARN("Failed to acknowledge the open request for endpoint #%d. %m", endpoint_id);
  } else if ((size_t)ret != buffer_len) {
    BUG("Failed to acknowledge the open request for endpoint #%d. Sent %d, Expected %d",
        endpoint_id, (int)ret, (int)buffer_len);
  }
}

/***************************************************************************//**
 * Common routine to finalize a request to open an endpoint, successful or not.
 * If the endpoint was successfully opened, the server will be notified to
 * create the endpoint socket, and a response will be sent to client on the
 * control socket.
 ******************************************************************************/
static void server_finalize_open_endpoint(uint8_t endpoint_id,
                                          sl_status_t status,
                                          void *server_ctx)
{
  pending_connection_list_item_t *connection = (pending_connection_list_item_t*)server_ctx;
  sl_slist_node_t *node;
  bool can_open;

  // remove first element from the list, that's the one we
  // expect to be processing now
  FATAL_ON(pending_connections == NULL);
  node = sl_slist_pop(&pending_connections);

  FATAL_ON(node != &connection->node);

  can_open = (status == SL_STATUS_OK);

  if (can_open) {
    server_open_endpoint(endpoint_id);
  }

  system_send_open_endpoint_ack(endpoint_id, can_open, connection);

  free(connection);
}

#if !defined(UNIT_TESTING)
static void system_noop_cmd_callback(sl_status_t status)
{
  switch (status) {
    case SL_STATUS_OK:
      TRACE_SERVER("NOOP success");
      break;
    case SL_STATUS_IN_PROGRESS:
      TRACE_SERVER("NOOP success with a least one retry");
      break;
    case SL_STATUS_TIMEOUT:
      WARN("The noop keep alive timed out, link dead");
      TRACE_SERVER("NOOP timed out!");
      break;
    case SL_STATUS_ABORT:
      WARN("The noop keep alive was aborted");
      TRACE_SERVER("NOOP failed!");
      break;
    default:
      FATAL();
      break;
  }
}

static void server_process_epoll_fd_timeout_noop(epoll_private_data_t *private_data)
{
  int fd_timer_noop = private_data->file_descriptor;

  /* Ack the timer */
  {
    uint64_t expiration;
    ssize_t retval;

    retval = read(fd_timer_noop, &expiration, sizeof(expiration));

    FATAL_SYSCALL_ON(retval < 0);

    FATAL_ON(retval != sizeof(expiration));

    WARN_ON(expiration != 1); /* we missed a timeout*/
  }

  TRACE_SERVER("NOOP keep alive");

  sl_cpc_system_cmd_noop(system_noop_cmd_callback,
                         5,
                         100000);
}
#endif

/*
 * The main loop calls this function when an endpoint connection socket is ready.
 * When this happens, it means that someone tries to establish a connection on
 * this named socket. An endpoint connection socket is not the one on which the data
 * transit, its just the one that waits for connections. When a connection occurs,
 * accept it and place the new data_socket in the list of data_sockets for that
 * endpoint number
 */
static void server_process_epoll_fd_ep_connection_socket(epoll_private_data_t *private_data)
{
  int new_data_socket, flags;
  int fd_connection_socket = private_data->file_descriptor;
  uint8_t endpoint_number = private_data->endpoint_number;

  /* Sanity checks */
  {
    /* We don't deal with system endpoint here*/
    BUG_ON(endpoint_number == 0);

    /* Make sure the connection socket exists */
    BUG_ON(endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor == -1);

    /* The server should not be currently connecting to the secondary */
    BUG_ON(endpoints[endpoint_number].connecting_data_socket_fd != -1);
  }

  /* Accept the new connection for that endpoint */
  new_data_socket = accept(fd_connection_socket, NULL, NULL);
  FATAL_SYSCALL_ON(new_data_socket < 0);

  /* Set socket as non-blocking */
  flags = fcntl(new_data_socket, F_GETFL, NULL);

  if (flags < 0) {
    FATAL("fcntl F_GETFL failed.%s", strerror(errno));
  }

  flags |= O_NONBLOCK;

  if (fcntl(new_data_socket, F_SETFL, flags) < 0) {
    FATAL("fcntl F_SETFL failed.%s", strerror(errno));
  }

  /*
   * store the newly created file descriptor as it will
   * be used when the secondary acks the connection
   */
  endpoints[endpoint_number].connecting_data_socket_fd = new_data_socket;

  /* unregister this entry to process only one connection request at a time */
  epoll_unregister(private_data);

  uint8_t tx_window_size = endpoints[endpoint_number].tx_window_size;

  /* Tell the core that a client has connected to this endpoint */
  if (endpoints[endpoint_number].open_data_connections == 0) {
    TRACE_SERVER("Told core to connect to ep#%u", endpoint_number);
    core_open_endpoint(endpoint_number, tx_window_size);
  } else {
    server_connect_endpoint(endpoint_number, false);
  }
}

static void server_process_epoll_fd_ep_data_socket(epoll_private_data_t *private_data)
{
  uint8_t* buffer;
  size_t buffer_len;
  int fd_data_socket = private_data->file_descriptor;
  uint8_t endpoint_number = private_data->endpoint_number;
  int ret;

  if (core_ep_is_busy(endpoint_number)) {
    /* Prevent epoll from unblocking right away on this [still marked as ready-read] file descriptor the next time
     * epoll_wait is called (and thus leading to 100% CPU usage) */
    epoll_unwatch(private_data);
    return;
  }

  /* Check if the event is about the client closing the connection */
  {
    int length;

    ret = ioctl(fd_data_socket, FIONREAD, &length);
    FATAL_SYSCALL_ON(ret < 0);

    if (length == 0) {
      server_handle_client_closed_ep_connection(fd_data_socket, endpoint_number);
      return;
    }
  }

  /* The event is about rx data */

  /* Retrieve the payload from the endpoint data connection */
  ret = server_pull_data_from_data_socket(fd_data_socket, &buffer, &buffer_len);
  if (ret != 0) {
    server_handle_client_closed_ep_connection(fd_data_socket, endpoint_number);
    return;
  }

  /* Send the data to the core */
  ret = core_write(endpoint_number, buffer, buffer_len, 0);
  if (ret != 0) {
    WARN("User tried to push on endpoint %d but it failed",
         endpoint_number);
    server_close_endpoint(endpoint_number, false);
  }
  free(buffer);
}

static void server_handle_client_disconnected(uint8_t endpoint_number)
{
  FATAL_ON(endpoints[endpoint_number].open_data_connections == 0);

  endpoints[endpoint_number].open_data_connections--;
  PRINT_INFO("Endpoint socket #%d: Client disconnected. %d connections", endpoint_number, endpoints[endpoint_number].open_data_connections);

  if (endpoints[endpoint_number].open_data_connections == 0) {
    TRACE_SERVER("Closing endpoint socket, no more listeners");
    server_close_endpoint(endpoint_number, false);

    if (endpoints[endpoint_number].pending_close == 0) {
      TRACE_SERVER("No pending close on the endpoint, closing it");
      core_close_endpoint(endpoint_number, true, false);
    }
  }
}

/***************************************************************************//**
 * Handle endpoint closed by client (cannot read, write, or EOF received)
 ******************************************************************************/
static void server_handle_client_closed_ep_connection(int fd_data_socket, uint8_t endpoint_number)
{
  sl_slist_node_t *it = endpoints[endpoint_number].data_connections;
  data_connection_t* item;

  /* The while loop that follows is the macro SL_SLIST_FOR_EACH_ENTRY exploded to allow
   * for free()ing items during iteration */

  if (it == NULL) {
    FATAL("data connection not found in the linked list of the endpoint");
  }

  while (it != NULL) {
    item = SL_SLIST_ENTRY(it,
                          data_connection_t,
                          node);

    /* Get next item */
    it = it->node;

    /* We are iterating through the linked list of opened connections,
     * check if this iteration is the good one*/
    if (item->conn_data_fd == fd_data_socket) {
      int ret;

      /* Unregister the data socket file descriptor from epoll watch list */
      epoll_unregister(&item->data_socket_epoll_private_data);

      /* Remove the item from the list*/
      sl_slist_remove(&endpoints[endpoint_number].data_connections, &item->node);

      /*
       * Notify the client. The client may or may not have initiated a close
       * request. If a close request was initiated, it means it's a clean close
       * notify the client and free the resource. If close request was not
       * initiated but we end up here, it means that the client probably
       * crashed. So just close and free regardless of the return value of the
       * function.
       */
      server_handle_client_closed_ep_notify_close(endpoint_number, item);

      /* Properly close this socket on our side (it is on the client's side)*/
      ret = close(item->conn_data_fd);
      FATAL_SYSCALL_ON(ret < 0);

      /* data connections items are malloced */
      free(item);

      /* Inform server and core that the endpoint lost a listener */
      server_handle_client_disconnected(endpoint_number);
    }
  }
}

static data_connection_t* server_find_data_connection(sl_slist_node_t *head, int conn_data_fd)
{
  data_connection_t *conn;

  if (head == NULL) {
    return NULL;
  }

  SL_SLIST_FOR_EACH_ENTRY(head, conn, data_connection_t, node) {
    if (conn->conn_data_fd == conn_data_fd) {
      return conn;
    }
  }

  return NULL;
}

static bool server_ep_remove_closed_connection(uint8_t endpoint_number, int conn_data_fd)
{
  sl_slist_node_t **head = &endpoints[endpoint_number].closed_data_connections;
  data_connection_t *conn = server_find_data_connection(*head, conn_data_fd);

  if (conn == NULL) {
    return false;
  }

  sl_slist_remove(head, &conn->node);

  /*
   * Close the file descriptor. It's done only now to make sure the file
   * descriptor is not reused while there is a closed connection with the same
   * file descriptor. Otherwise we could end up with:
   *  - Client A
   *    - open endpoint X, get conn_data_fd=42
   *    - crash
   *    - daemon detects that socket is closed and put the connection in the
   *      closed connections list.
   *  - Client B
   *    - open endpoint X, get conn_data_fd=42 (reused)
   *    - close endpoint, the daemon detects that the data socket with fd=42
   *      has already been closed and returns immediately to the client, but
   *      it's actually confusing the current connection with the one of
   *      client A
   */
  close(conn->conn_data_fd);

  free(conn);

  return true;
}

static void server_ep_mark_close_pending(uint8_t endpoint_number, int conn_data_fd, int conn_ctrl_fd)
{
  sl_slist_node_t **head = &endpoints[endpoint_number].data_connections;
  data_connection_t *conn = server_find_data_connection(*head, conn_data_fd);

  if (conn != NULL) {
    conn->conn_ctrl_fd = conn_ctrl_fd;
  }
}

static bool server_handle_client_closed_ep_notify_close(uint8_t endpoint_number, data_connection_t *conn)
{
  bool notified = false;

  if (conn->conn_ctrl_fd > 0) {
    ssize_t ret;
    uint8_t query_close_buffer[sizeof(cpcd_exchange_buffer_t) + sizeof(int)];
    const size_t query_close_len = sizeof(cpcd_exchange_buffer_t) + sizeof(int);
    cpcd_exchange_buffer_t *query_close = (cpcd_exchange_buffer_t *)query_close_buffer;

    query_close->endpoint_number = endpoint_number;
    query_close->type = EXCHANGE_CLOSE_ENDPOINT_QUERY;
    memcpy(query_close->payload, &conn->conn_data_fd, sizeof(conn->conn_data_fd));

    ret = send(conn->conn_ctrl_fd, query_close, query_close_len, 0);
    if (ret == (ssize_t)query_close_len) {
    } else {
      if (errno != EPIPE || errno != ECONNRESET || errno != ECONNREFUSED) {
        WARN("Endpoint close notification could not be sent, errno = %d", errno);
      }
    }

    notified = true;
  }

  return notified;
}

static void server_handle_client_closed_ctrl_connection(int fd_data_socket)
{
  ctrl_socket_private_data_list_item_t* item;
  sl_slist_node_t *it = ctrl_connections;

  /* The while loop that follows is the macro SL_SLIST_FOR_EACH_ENTRY exploded to allow
   * for free()ing items during iteration */

  if (it == NULL) {
    FATAL("ctrl data connection not found in the linked list of the ctrl socket");
  }

  while (it != NULL) {
    item = SL_SLIST_ENTRY(it,
                          ctrl_socket_private_data_list_item_t,
                          node);

    /* Get the next item */
    it = it->node;

    /* We are iterating through the linked list of opened connections,
     * check if this iteration is the good one*/
    if (item->data_socket_epoll_private_data.file_descriptor == fd_data_socket) {
      /* Unregister the data socket file descriptor from epoll watch list */
      epoll_unregister(&item->data_socket_epoll_private_data);

      /* Remove the item from the list*/
      sl_slist_remove(&ctrl_connections, &item->node);

      /* Properly close this socket on our side (it is on the client's side)*/
      int ret = close(fd_data_socket);
      FATAL_SYSCALL_ON(ret < 0);

      PRINT_INFO("Client disconnected");

      /* data connections items are malloced */
      free(item);
    }
  }
}

static void server_handle_client_closed_reset_connection(int fd_reset_data_socket)
{
  reset_socket_private_data_list_item_t* item;
  sl_slist_node_t *it = reset_connections;

  /* The while loop that follows is the macro SL_SLIST_FOR_EACH_ENTRY exploded to allow
   * for free()ing items during iteration */

  if (it == NULL) {
    FATAL("reset data connection not found in the linked list of the reset socket");
  }

  while (it != NULL) {
    item = SL_SLIST_ENTRY(it,
                          reset_socket_private_data_list_item_t,
                          node);

    /* Get the next item */
    it = it->node;

    /* We are iterating through the linked list of opened connections,
     * check if this iteration is the good one*/
    if (item->reset_socket_epoll_private_data.file_descriptor == fd_reset_data_socket) {
      /* Unregister the reset data socket file descriptor from epoll watch list */
      epoll_unregister(&item->reset_socket_epoll_private_data);

      /* Remove the item from the list*/
      sl_slist_remove(&reset_connections, &item->node);

      /* Properly close this socket on our side (it is on the client's side)*/
      int ret = close(fd_reset_data_socket);
      FATAL_SYSCALL_ON(ret < 0);

      /* data connections items are malloced */
      free(item);
    }
  }
}

static void server_handle_client_closed_event_connection(int fd_data_socket, uint8_t endpoint_number)
{
  event_socket_private_data_list_item_t* item;
  sl_slist_node_t *it = endpoints[endpoint_number].event_data_socket_epoll_private_data;

  BUG_ON(endpoints[endpoint_number].open_event_connections == 0);

  /* The while loop that follows is the macro SL_SLIST_FOR_EACH_ENTRY exploded to allow
   * for free()ing items during iteration */

  if (it == NULL) {
    FATAL("event data connection not found in the linked list of the event socket");
  }

  while (it != NULL) {
    item = SL_SLIST_ENTRY(it,
                          event_socket_private_data_list_item_t,
                          node);

    /* Get the next item */
    it = it->node;

    /* We are iterating through the linked list of opened connections,
     * check if this iteration is the good one*/
    if (item->event_socket_epoll_private_data.file_descriptor == fd_data_socket) {
      /* Unregister the data socket file descriptor from epoll watch list */
      epoll_unregister(&item->event_socket_epoll_private_data);

      /* Remove the item from the list*/
      sl_slist_remove(&endpoints[endpoint_number].event_data_socket_epoll_private_data, &item->node);

      /* Properly close this socket on our side (it is on the client's side)*/
      int ret = close(fd_data_socket);
      FATAL_SYSCALL_ON(ret < 0);

      /* data connections items are malloced */
      free(item);
    }
  }

  endpoints[endpoint_number].open_event_connections--;
  PRINT_INFO("Endpoint event socket #%u: Client disconnected (%d). %d connections", endpoint_number, fd_data_socket, endpoints[endpoint_number].open_event_connections);
}

static void server_set_tx_window_size(uint8_t endpoint_id, uint8_t tx_window_size)
{
  endpoints[endpoint_id].tx_window_size = tx_window_size;
}

static void server_open_endpoint_event_socket(uint8_t endpoint_number)
{
  struct sockaddr_un name;
  int fd_connection_sock;
  int ret;

  /* Sanity checks */
  {
    if (endpoints[endpoint_number].event_connection_socket_epoll_private_data.file_descriptor != -1) {
      return; // Nothing to do, endpoint socket is already opened
    }

    /* System endpoint (#0) is not like the others, if we create a socket for it, there's a bug */
    BUG_ON(endpoint_number == 0);

    /* Its a bug if we try to open an already opened endpoint */
    BUG_ON(endpoints[endpoint_number].event_connection_socket_epoll_private_data.file_descriptor != -1);

    /* Make sure the list of data sockets is empty (no leftovers from previous open/close */
    BUG_ON(endpoints[endpoint_number].event_data_socket_epoll_private_data != NULL);
  }

  /* Create the connection socket and start listening new connections on /run/cpc/epX.cpcd.sock */
  {
    /* Create the connection socket.*/
    fd_connection_sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    FATAL_SYSCALL_ON(fd_connection_sock < 0);

    /* Bind this socket to a name. */
    {
      /*
       * For portability clear the whole structure, since some
       * implementations have additional (nonstandard) fields in
       * the structure.
       */
      memset(&name, 0, sizeof(name));

      name.sun_family = AF_UNIX;

      /* Create the endpoint socket path */
      {
        int nchars;
        const size_t size = sizeof(name.sun_path) - 1;

        nchars = snprintf(name.sun_path, size, "%s/cpcd/%s/ep%d.event.cpcd.sock", config.socket_folder, config.instance_name, endpoint_number);

        /* Make sure the path fitted entirely in the struct's static buffer */
        FATAL_ON(nchars < 0 || (size_t) nchars >= size);
      }

      ret = bind(fd_connection_sock, (const struct sockaddr *) &name, sizeof(name));
      FATAL_SYSCALL_ON(ret < 0);
    }

    /*
     * Prepare for accepting connections. The backlog size is set
     * to 5. So while one request is being processed other requests
     * can be waiting.
     */
    ret = listen(fd_connection_sock, 5);
    FATAL_SYSCALL_ON(ret < 0);
  }

  /* Start monitoring this connection socket in epoll */
  {
    epoll_private_data_t* private_data = &endpoints[endpoint_number].event_connection_socket_epoll_private_data;

    private_data->callback = server_process_epoll_fd_event_connection_socket;
    private_data->endpoint_number = endpoint_number;
    private_data->file_descriptor = fd_connection_sock;

    epoll_register(private_data);
  }

  PRINT_INFO("Opened connection event socket for ep#%u", endpoint_number);
}

/*
 * This function creates AF_UNIX::SOCK_SEQPACKET named connection socket
 * in /tmp/cpcd/epX.cpcd.sock, adds it to the list of connection sockets and listen
 * to it.
 */
static void server_open_endpoint(uint8_t endpoint_number)
{
  struct sockaddr_un name;
  int fd_connection_sock;
  int ret;

  /* Sanity checks */
  {
    if (endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor != -1) {
      return; // Nothing to do, endpoint socket is already opened
    }

    /* System endpoint (#0) is not like the others, if we create a socket for it, there's a bug */
    BUG_ON(endpoint_number == 0);

    /* Its a bug if we try to open an already opened endpoint */
    BUG_ON(endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor != -1);

    /* Make sure the list of data sockets is empty (no leftovers from previous open/close */
    BUG_ON(endpoints[endpoint_number].data_connections != NULL);
  }

  /* Create the connection socket and start listening new connections on /run/cpc/epX.cpcd.sock */
  {
    /* Create the connection socket.*/
    fd_connection_sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    FATAL_SYSCALL_ON(fd_connection_sock < 0);

    /* Bind this socket to a name. */
    {
      /*
       * For portability clear the whole structure, since some
       * implementations have additional (nonstandard) fields in
       * the structure.
       */
      memset(&name, 0, sizeof(name));

      name.sun_family = AF_UNIX;

      /* Create the endpoint socket path */
      {
        int nchars;
        const size_t size = sizeof(name.sun_path) - 1;

        nchars = snprintf(name.sun_path, size, "%s/cpcd/%s/ep%d.cpcd.sock", config.socket_folder, config.instance_name, endpoint_number);

        /* Make sure the path fitted entirely in the struct's static buffer */
        FATAL_ON(nchars < 0 || (size_t) nchars >= size);
      }

      ret = bind(fd_connection_sock, (const struct sockaddr *) &name, sizeof(name));
      FATAL_SYSCALL_ON(ret < 0);
    }

    /*
     * Prepare for accepting connections. The backlog size is set
     * to 5. So while one request is being processed other requests
     * can be waiting.
     */
    ret = listen(fd_connection_sock, 5);
    FATAL_SYSCALL_ON(ret < 0);
  }

  /* Start monitoring this connection socket in epoll */
  {
    epoll_private_data_t* private_data = &endpoints[endpoint_number].connection_socket_epoll_private_data;

    private_data->callback = server_process_epoll_fd_ep_connection_socket;
    private_data->endpoint_number = endpoint_number; /* server_process_epoll_fd_ep_connection_socket() callback WILL use the endpoint number and the file descriptor */
    private_data->file_descriptor = fd_connection_sock;

    epoll_register(private_data);
  }

  PRINT_INFO("Opened connection socket for ep#%u", endpoint_number);
}

bool server_is_endpoint_open(uint8_t endpoint_number)
{
  return endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor == -1 ? false : true;
}

/*
 * Connect an endpoint for the end user
 *
 * It means that the secondary replied successfully to a connection request, so
 * the server should start watching the data socket for incoming packets and
 * allow other clients to connect to the endpoint
 */
void server_connect_endpoint(uint8_t endpoint_number, bool error)
{
  size_t buffer_len = sizeof(cpcd_exchange_buffer_t) + sizeof(int) + sizeof(bool);
  int data_socket_fd = endpoints[endpoint_number].connecting_data_socket_fd;
  cpcd_exchange_buffer_t *buffer;
  uint8_t payload[buffer_len];
  bool can_open = !error;
  ssize_t sent_bytes;

  BUG_ON(data_socket_fd == -1);

  if (!error) {
    /*
     * If no error occurred, the secondary accepted the connection request,
     * start watching on the data socket created for the user
     */
    data_connection_t* new_item;
    epoll_private_data_t* private_data;

    new_item = (data_connection_t*) zalloc(sizeof(*new_item));
    FATAL_SYSCALL_ON(new_item == NULL);

    new_item->conn_data_fd = data_socket_fd;
    new_item->conn_ctrl_fd = -1;

    private_data = &new_item->data_socket_epoll_private_data;
    private_data->callback = server_process_epoll_fd_ep_data_socket;
    private_data->endpoint_number = endpoint_number;
    private_data->file_descriptor = data_socket_fd;

    /* Add the new data socket in the list of data sockets for that endpoint */
    sl_slist_push(&endpoints[endpoint_number].data_connections, &new_item->node);

    /* Register this new connection's socket to epoll set */
    epoll_register(private_data);

    endpoints[endpoint_number].open_data_connections++;
    PRINT_INFO("Endpoint socket #%d: Client connected. %d connection(s)",
               endpoint_number, endpoints[endpoint_number].open_data_connections);
  }

  buffer = (cpcd_exchange_buffer_t*) payload;

  buffer->endpoint_number = endpoint_number;
  buffer->type = EXCHANGE_OPEN_ENDPOINT_QUERY;

  /*
   * Share the server endpoint data socket to the user. This allows us to
   * create a ctrl data/data socket pair when it's time to close the socket,
   * which ultimately allows us to send a synchronized notification to the user.
   * For the library, this variable is just a token that the user must pass
   * back to the daemon in order to identify the connection. The library uses
   * that value as session_id.
   */
  memcpy(buffer->payload, &data_socket_fd, sizeof(data_socket_fd));
  memcpy(&buffer->payload[sizeof(int)], &can_open, sizeof(bool));

  sent_bytes = send(data_socket_fd, buffer, buffer_len, 0);
  if (sent_bytes != (ssize_t)buffer_len) {
    if (errno == EPIPE) {
      WARN("User endpoint disconnected before connection reply could be sent");
      server_handle_client_closed_ep_connection(data_socket_fd, endpoint_number);
    } else {
      FATAL("Failed reply to connection request: %m");
    }
  }

  /* for sanity, reset this value to -1 to catch potential mistakes */
  endpoints[endpoint_number].connecting_data_socket_fd = -1;

  /* watch back the connection socket for other clients wishing to connect */
  epoll_register(&endpoints[endpoint_number].connection_socket_epoll_private_data);
}

/* Close an endpoint in the server layer
 *
 * Closing an endpoint means to close every active connection (data socket) with client applications,
 * and at last close the connection socket that is bound to the /run/cpc/epX.cpcd.sock.
 */
void server_close_endpoint(uint8_t endpoint_number, bool error)
{
  size_t data_sock_i = 0;
  int ret;

  /* Sanity check */
  {
    /* System endpoint is not like the others, if we create a socket for it, there's a bug */
    BUG_ON(endpoint_number == 0);

    if (endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor == -1) {
      return; // Endpoint was previously closed
    }
  }

  /* Close every open connection on that endpoint (data socket) */
  while (endpoints[endpoint_number].data_connections != NULL) {
    data_connection_t* item;
    bool client_notified;
    data_sock_i++;

    /* Pop the first element of the list */
    {
      sl_slist_node_t* node = sl_slist_pop(&endpoints[endpoint_number].data_connections);

      item = SL_SLIST_ENTRY(node, data_connection_t, node);
    }

    /* Unregister the data socket file descriptor from epoll watch list */
    {
      epoll_unregister(&item->data_socket_epoll_private_data);
    }

    /* Notify the client */
    {
      client_notified = server_handle_client_closed_ep_notify_close(endpoint_number, item);

      /*
       * If the client was notified, it means a close request was pending, now
       * that we're done dealing with it, we can get rid of it. Otherwise, just
       * shutdown the connection to prevent client from using it. Eventually, we
       * expect them to close the endpoint via the control endpoint. If the
       * error flag is set, all connection resources should be released.
       */
      if (client_notified || error) {
        /* Close the socket */
        ret = close(item->conn_data_fd);
        FATAL_SYSCALL_ON(ret < 0);

        /* Unlike connection sockets, which is one per endpoint (and we know there are 255 of them)
         * and statically allocated in the fixed 255 size array at the top of this file, data sockets
         * are dynamically allocated because an arbitrary number of application can decide to connect
         * to an opened endpoint */
        /* Linked list items are malloc'ed, free them */
        free(item);
      } else {
        /* shutdown the socket to prevent further transmissions */
        ret = shutdown(item->conn_data_fd, SHUT_RDWR);
        FATAL_SYSCALL_ON(ret < 0);

        sl_slist_push_back(&endpoints[endpoint_number].closed_data_connections,
                           &item->node);
      }

      TRACE_SERVER("Closed data socket #%u on ep#%u%s",
                   data_sock_i,
                   endpoint_number,
                   client_notified ? "" : " delayed");
    }
  }

  /* Close the connection socket */
  {
    int fd_connection_socket = endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor;

    if (fd_connection_socket > 0) {
      /* Unregister the connection socket file descriptor from epoll watch list */
      epoll_unregister(&endpoints[endpoint_number].connection_socket_epoll_private_data);

      /* Close the connection socket */
      ret = close(fd_connection_socket);
      FATAL_SYSCALL_ON(ret < 0);
    }

    /* Clean its lingering file system socket file */
    {
      /* The connection socket was named and bound to a file system name. Shutting() it down
       * and closing() it doesn't 'delete' its file, it has to be manually unlinked */
      char endpoint_path[sizeof_member(struct sockaddr_un, sun_path)];

      /* Create the endpoint path */
      {
        int nchars;
        const size_t size = sizeof(endpoint_path);

        nchars = snprintf(endpoint_path, size, "%s/cpcd/%s/ep%d.cpcd.sock", config.socket_folder, config.instance_name, endpoint_number);

        /* Make sure the path fitted entirely in the struct's static buffer */
        FATAL_ON(nchars < 0 || (size_t) nchars >= size);
      }

      ret = unlink(endpoint_path);
      FATAL_SYSCALL_ON(ret < 0 && errno != ENOENT);
    }

    /* Set the connection socket file descriptor to -1 to signify that the endpoint is closed */
    endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor = -1;

    /* At this point the endpoint socket is closed.. there can't be any listeners */
    if (error) {
      // We expect all open connections to call cpc_close to clear the error via the control socket
      endpoints[endpoint_number].pending_close = endpoints[endpoint_number].open_data_connections;
    }
    endpoints[endpoint_number].open_data_connections = 0;
  }
}

/* Send data to all connected apps on a given endpoint
 *
 * When the server retrieves endoint data from the core, it calls this function to
 * forward the data out of the daemon to all the connected apps.
 */
sl_status_t server_push_data_to_endpoint(uint8_t endpoint_number, const uint8_t* data, size_t data_len)
{
  sl_slist_node_t *it = endpoints[endpoint_number].data_connections;
  int nb_clients = 0;

  /* Sanity checks */
  {
    /* If we receive data for an endpoint from the core and try to push it to an
     * endpoint socket that is closed (that is, doesn't have its connection socket
     * up), its a bug. Server and core should be coherent */
    BUG_ON(endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor == -1);

    /* Give a warning if we want to push data but no apps are connected to the
     * endpoint. That is, the list of data sockets is empty */
    WARN_ON(endpoints[endpoint_number].data_connections == NULL);
  }

  /* Iterate through all data sockets for that endpoint */
  while (it != NULL) {
    /* Push the buffer's payload to each connected app */
    data_connection_t *item = SL_SLIST_ENTRY(it, data_connection_t, node);
    ssize_t wc;

    it = it->node;

    wc = send(item->conn_data_fd,
              data,
              data_len,
              MSG_DONTWAIT);
    if (wc < 0) {
      TRACE_SERVER("send() failed with %s", strerror(errno));
    }

    /* keep track of number of clients the data have been sent to */
    nb_clients++;

    /* Close unresponsive sockets */
    if (wc < 0 && (errno == EAGAIN || errno == EPIPE || errno == ECONNRESET || errno == EWOULDBLOCK)) {
      WARN("Unresponsive data socket on ep#%d, closing", endpoint_number);

      /*
       * nb_clients helps to keep track of the number of clients the data have
       * been sent to. The use case here is to return an error *only* if there
       * was only one client connected. If there were two clients and for some
       * reasons sending to both of them fail, we want to close the two connections.
       */
      if (endpoints[endpoint_number].open_data_connections == 1 && nb_clients == 1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          return SL_STATUS_WOULD_BLOCK;
        }
      }

      /* Unregister the data socket file descriptor from epoll watch list */
      epoll_unregister(&item->data_socket_epoll_private_data);

      /* shutdown the socket, preventing further transmissions */
      int ret = shutdown(item->conn_data_fd, SHUT_RDWR);
      FATAL_SYSCALL_ON(ret < 0);

      /* Remove the item from the list*/
      sl_slist_remove(&endpoints[endpoint_number].data_connections, &item->node);

      /* Push item to list of closed data endpoints */
      sl_slist_push_back(&endpoints[endpoint_number].closed_data_connections, &item->node);

      FATAL_ON(endpoints[endpoint_number].open_data_connections == 0);

      endpoints[endpoint_number].open_data_connections--;
      PRINT_INFO("Endpoint socket #%d: Client disconnected. %d connection(s)",
                 endpoint_number, endpoints[endpoint_number].open_data_connections);

      if (endpoints[endpoint_number].open_data_connections == 0) {
        TRACE_SERVER("Endpoint was unresponsive, closing endpoint socket, no more listeners");
        server_close_endpoint(endpoint_number, false);
        return SL_STATUS_FAIL;
      }
    } else {
      /* The data should have been be completely written to the socket */
      FATAL_SYSCALL_ON(wc < 0);
      FATAL_ON((size_t)wc != data_len);
    }
  }

  return SL_STATUS_OK;
}

static int server_pull_data_from_data_socket(int fd_data_socket, uint8_t** buffer_ptr, size_t* buffer_len_ptr)
{
  int datagram_length;
  uint8_t* buffer;
  ssize_t rc;
  int ret;

  /* Poll the socket to get the next pending datagram size */
  {
    ret = ioctl(fd_data_socket, FIONREAD, &datagram_length);

    FATAL_SYSCALL_ON(ret < 0);

    /* The socket had no data. This function is intended to be called
     * when we know the socket has data. */
    BUG_ON(datagram_length == 0);
  }

  /* Allocate a buffer of the right size */
  {
    // Allocate a buffer and pad it to 8 bytes because memcpy reads in chunks of 8.
    // If we don't pad, Valgrind will complain.
    buffer = (uint8_t*) zalloc((size_t)PAD_TO_8_BYTES(datagram_length));
    FATAL_ON(buffer == NULL);
  }

  /* Fetch the data from the data socket */
  {
    rc = recv(fd_data_socket, buffer, (size_t)datagram_length, 0);
    if (rc < 0) {
      TRACE_SERVER("recv() failed with %s", strerror(errno));
    }

    if (rc == 0 || (rc < 0 && errno == ECONNRESET)) {
      TRACE_SERVER("Client is closed");
      free(buffer);
      return -1;
    }
    FATAL_SYSCALL_ON(rc < 0);
  }

  *buffer_ptr = buffer;
  *buffer_len_ptr = (size_t)rc;
  return 0;
}

bool server_listener_list_empty(uint8_t endpoint_number)
{
  return endpoints[endpoint_number].open_data_connections == 0;
}

void server_listener_shutdown(uint8_t endpoint_number)
{
  data_connection_t *conn;

  if (endpoints[endpoint_number].data_connections == NULL) {
    return;
  }

  SL_SLIST_FOR_EACH_ENTRY(endpoints[endpoint_number].data_connections,
                          conn,
                          data_connection_t,
                          node) {
    int ret;

    ret = shutdown(conn->conn_data_fd, SHUT_RD);
    if (ret != 0) {
      WARN("Failed to shutdown connection for ep #%d, conn #%d, errno %d",
           endpoint_number, conn->conn_data_fd, errno);
    }
  }
}

void server_notify_connected_libs_of_secondary_reset(void)
{
  reset_socket_private_data_list_item_t* item;

  SL_SLIST_FOR_EACH_ENTRY(reset_connections,
                          item,
                          reset_socket_private_data_list_item_t,
                          node){
    ssize_t ret = send(item->reset_socket_epoll_private_data.file_descriptor, NULL, 0, MSG_DONTWAIT);
    if (ret < 0 && (errno != EPIPE || errno != ECONNRESET || errno != ECONNREFUSED)) {
      WARN("Reset callback notification could not be sent, errno = %d", errno);
    }
  }
}

static void server_send_event(int socket_fd, cpc_event_type_t event_type, uint8_t ep_id, uint8_t *payload, uint32_t payload_length)
{
  cpcd_event_buffer_t *event = zalloc(sizeof(cpcd_event_buffer_t) + payload_length);
  FATAL_SYSCALL_ON(event == NULL);

  event->type = event_type;
  event->endpoint_number = ep_id;
  event->payload_length = payload_length;

  if (payload != NULL && payload_length > 0) {
    memcpy(event->payload, payload, payload_length);
  }

  ssize_t ret = send(socket_fd, event, sizeof(cpcd_event_buffer_t) + payload_length, MSG_DONTWAIT);

  if (ret < 0 && (errno == EPIPE || errno == ECONNRESET || errno == ECONNREFUSED)) {
    // Do nothing on a closed socket server_handle_client_closed_event_connection will be called by an epoll event
  } else if (ret < 0 && errno == EWOULDBLOCK) {
    WARN("Client event socket is full, closing the socket..");
    // User is not listening to the event socket..
    // Properly shutdown this socket on our side.
    // Resources will be freed in the server_handle_client_closed_event_connection callback
    ret = shutdown(socket_fd, SHUT_RDWR);
    FATAL_SYSCALL_ON(ret < 0);
  } else {
    BUG_ON(ret < 0 || (size_t)ret != sizeof(cpcd_event_buffer_t) + payload_length);
  }

  free(event);
}

static cpc_event_type_t server_get_event_type_from_state(sli_cpc_endpoint_state_t state)
{
  switch (state) {
    case SLI_CPC_STATE_CONNECTED:
      return SL_CPC_EVENT_ENDPOINT_OPENED;
    case SLI_CPC_STATE_CLOSED:
      return SL_CPC_EVENT_ENDPOINT_CLOSED;
    case SLI_CPC_STATE_CLOSING:
      return SL_CPC_EVENT_ENDPOINT_CLOSING;
    case SLI_CPC_STATE_ERROR_DESTINATION_UNREACHABLE:
      return SL_CPC_EVENT_ENDPOINT_ERROR_DESTINATION_UNREACHABLE;
    case SLI_CPC_STATE_ERROR_SECURITY_INCIDENT:
      return SL_CPC_EVENT_ENDPOINT_ERROR_SECURITY_INCIDENT;
    case SLI_CPC_STATE_ERROR_FAULT:
      return SL_CPC_EVENT_ENDPOINT_ERROR_FAULT;
    case SLI_CPC_STATE_FREED:
    case SLI_CPC_STATE_OPEN:
    case SLI_CPC_STATE_CONNECTING:
    case SLI_CPC_STATE_SHUTTING_DOWN:
    case SLI_CPC_STATE_SHUTDOWN:
    case SLI_CPC_STATE_REMOTE_SHUTDOWN:
    case SLI_CPC_STATE_DISCONNECTED:
      return SL_CPC_EVENT_ENDPOINT_UNKNOWN;
    default:
      BUG("A new state (%d) has been added that has no equivalent event type .", state);
  }
}

static void server_notify_connected_libs_of_endpoint_state_change(uint8_t ep_id, sli_cpc_endpoint_state_t new_state)
{
  event_socket_private_data_list_item_t* item;

  BUG_ON(ep_id == SL_CPC_ENDPOINT_SYSTEM || ep_id == SL_CPC_ENDPOINT_SECURITY);

  SL_SLIST_FOR_EACH_ENTRY(endpoints[ep_id].event_data_socket_epoll_private_data, item,
                          event_socket_private_data_list_item_t,
                          node){
    cpc_event_type_t event = server_get_event_type_from_state((new_state));
    if (event != 0) {
      server_send_event(item->event_socket_epoll_private_data.file_descriptor,
                        event,
                        ep_id,
                        NULL,
                        0);
    }
  }
}

void server_on_endpoint_state_change(uint8_t ep_id, sli_cpc_endpoint_state_t state)
{
  if (ep_id != SL_CPC_ENDPOINT_SYSTEM && ep_id != SL_CPC_ENDPOINT_SECURITY ) {
    server_notify_connected_libs_of_endpoint_state_change(ep_id, state);
  }
}
