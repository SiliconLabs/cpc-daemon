/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Server
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

#include "misc/errno_codename.h"
#include "misc/logging.h"
#include "misc/config.h"
#include "misc/utils.h"
#include "misc/sl_slist.h"
#include "server_core/server/server.h"
#include "server_core/server/server_internal.h"
#include "server_core/server/server_ready_sync.h"
#include "server_core/server_core.h"
#include "server_core/system_endpoint/system_callbacks.h"
#include "server_core/system_endpoint/system.h"
#include "server_core/epoll/epoll.h"
#include "server_core/core/core.h"
#include "server_core/cpcd_exchange.h"
#include "version.h"

/*******************************************************************************
 ***************************  LOCAL DECLARATIONS   *****************************
 ******************************************************************************/

typedef struct {
  sl_slist_node_t node;
  uint8_t endpoint_id;
  int fd_ctrl_data_socket;
}pending_connection_list_item_t;

typedef struct {
  sl_slist_node_t node;
  epoll_private_data_t data_socket_epoll_private_data;
  pid_t pid;
}ctrl_socket_private_data_list_item_t;

typedef struct {
  sl_slist_node_t node;
  epoll_private_data_t data_socket_epoll_private_data;
}data_socket_private_data_list_item_t;

typedef struct {
  uint32_t open_connections;
  uint32_t pending_close;
  epoll_private_data_t connection_socket_epoll_private_data;
  sl_slist_node_t* data_socket_epoll_private_data;
}endpoint_control_block_t;

/*******************************************************************************
 ***************************  GLOBAL VARIABLES   *******************************
 ******************************************************************************/

endpoint_control_block_t endpoints[256];

/* List to keep track of libraries that are blocking on the cpc_open call */
static sl_slist_node_t *pending_connections;

/* List to keep track of every connected library instance over the control socket */
static sl_slist_node_t *ctrl_connections;

/*******************************************************************************
 ***************************  LOCAL VARIABLES   ********************************
 ******************************************************************************/

static int fd_socket_ctrl;

/*******************************************************************************
 **************************   LOCAL FUNCTIONS   ********************************
 ******************************************************************************/

#if !defined(UNIT_TESTING)
static void server_process_epoll_fd_timeout_noop(epoll_private_data_t *private_data);
#endif

static void server_process_epoll_fd_ctrl_connection_socket(epoll_private_data_t *private_data);
static void server_process_epoll_fd_ctrl_data_socket(epoll_private_data_t *private_data);
static void server_process_epoll_fd_ep_connection_socket(epoll_private_data_t *private_data);
static void server_process_epoll_fd_ep_data_socket(epoll_private_data_t *private_data);

static void server_handle_client_disconnected(uint8_t endpoint_number);
static void server_handle_client_closed_ep_connection(int fd_data_socket, uint8_t endpoint_number);
static void server_handle_client_closed_ctrl_connection(int fd_data_socket);
static int server_pull_data_from_data_socket(int fd_data_socket, uint8_t** buffer_ptr, size_t* buffer_len_ptr);

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

        nchars = snprintf(name.sun_path, size, "%s/cpcd/%s/ctrl.cpcd.sock", config_socket_folder, config_instance_name);

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

  /* Initialize every endpoint control block */
  {
    size_t i;

    for (i = 1; i != 256; i++) { /* dont care for ep#0 */
      endpoints[i].open_connections = 0;
      endpoints[i].pending_close = 0;
      endpoints[i].connection_socket_epoll_private_data.endpoint_number = (uint8_t)i;
      endpoints[i].connection_socket_epoll_private_data.file_descriptor = -1;
      sl_slist_init(&endpoints[i].data_socket_epoll_private_data);
    }
  }

  /* Setup no-op timer. Trig in 1 sec, and every 1 sec after that */
  if (config_use_noop_keep_alive) {
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

    /* per-endpoint connection sockets are dynamically created [and added to epoll set] when endpoints are opened */

    /* per-endpoint data sockets are dynamically created [and added to epoll set] when instances of library are connecting to an endpoint */
  }

  /* The server up and running, unblock possible threads waiting for it. */
  server_ready_post();
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
    new_item = calloc(1, sizeof *new_item);
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
      cpc_endpoint_state_t ep_state;
      TRACE_SERVER("Received an endpoint status query");

      BUG_ON(buffer_len != sizeof(cpcd_exchange_buffer_t) + sizeof(cpc_endpoint_state_t));

      ep_state = core_get_endpoint_state(interface_buffer->endpoint_number);

      memcpy(interface_buffer->payload, &ep_state, sizeof(cpc_endpoint_state_t));

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
      TRACE_SERVER("Received an maximum write size query");

      BUG_ON(buffer_len != sizeof(cpcd_exchange_buffer_t) + sizeof(uint32_t));
      size_t rx_capability = (size_t)server_core_get_secondary_rx_capability();
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
      uint8_t* version = (uint8_t*) interface_buffer->payload;
      bool do_close_client = false;

      FATAL_ON(interface_buffer->payload == NULL);

      TRACE_SERVER("Received a version query");

      if (buffer_len != sizeof(cpcd_exchange_buffer_t) + sizeof(uint8_t)) {
        WARN("Client used invalid library version, buffer_len = %zu", buffer_len);
        break;
      }

      if (*version != LIBRARY_API_VERSION) {
        do_close_client = true;
        WARN("Client used invalid library version, (v%d) expected (v%d)", *version, LIBRARY_API_VERSION);
      }

      PRINT_INFO("Client is using library v%d", *version);

      //Reuse the receive buffer to send back the response
      *version = LIBRARY_API_VERSION;

      ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

      if ((ret < 0 && errno == EPIPE) || do_close_client) {
        server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
      } else {
        FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
        FATAL_ON((size_t)ret != sizeof(cpcd_exchange_buffer_t) + sizeof(uint8_t));
      }
    }
    break;

    case EXCHANGE_OPEN_ENDPOINT_QUERY:
      /* Client requested to open an endpoint socket*/
    {
      TRACE_SERVER("Received an endpoint open query");

      BUG_ON(buffer_len != sizeof(cpcd_exchange_buffer_t) + sizeof(bool));

      //Be careful when asked about opening the security endpoint...
      if (interface_buffer->endpoint_number == SL_CPC_ENDPOINT_SECURITY) {
        if (endpoints[SL_CPC_ENDPOINT_SECURITY].data_socket_epoll_private_data != NULL // Make sure only 1 client is connected (ie, the daemon' security thread)
            || config_use_encryption == false) {                                      // Make sure security is enabled
          // Reuse the same buffer to send a negative reply
          *(bool*)(interface_buffer->payload) = false;

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

      /* Add this connection to the pending connections list, we need to check the secondary if the endpoint is open */
      /* This will be done in the server_process_pending_connections function */
      pending_connection_list_item_t *pending_connection = malloc(sizeof(pending_connection_list_item_t));
      FATAL_ON(pending_connection == NULL);

      pending_connection->endpoint_id = interface_buffer->endpoint_number;
      pending_connection->fd_ctrl_data_socket = fd_ctrl_data_socket;
      sl_slist_push(&pending_connections, &pending_connection->node);
    }
    break;

    case EXCHANGE_CLOSE_ENDPOINT_QUERY:
    {
      TRACE_SERVER("Received a endpoint close query");
      if (endpoints[interface_buffer->endpoint_number].pending_close > 0) {
        endpoints[interface_buffer->endpoint_number].pending_close--;
        if (endpoints[interface_buffer->endpoint_number].pending_close == 0) {
          core_close_endpoint(interface_buffer->endpoint_number, true, false);
        }
      }

      ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

      if (ret < 0 && errno == EPIPE) {
        server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
      } else {
        FATAL_SYSCALL_ON(ret < 0 && errno != EPIPE);
        FATAL_ON((size_t)ret != sizeof(cpcd_exchange_buffer_t));
      }
    }
    break;

    case EXCHANGE_SET_PID_QUERY:
    {
      ctrl_socket_private_data_list_item_t* item;

      item = container_of(private_data, ctrl_socket_private_data_list_item_t, data_socket_epoll_private_data);

      item->pid = *(pid_t*)interface_buffer->payload;
    }
    break;

    default:
      break;
  }

  free(buffer);
}

void server_process_pending_connections(void)
{
  pending_connection_list_item_t *pending_connection;
  pending_connection = SL_SLIST_ENTRY(pending_connections, pending_connection_list_item_t, node);

  if (pending_connection != NULL && sl_cpc_system_is_waiting_for_status_reply() == false) {
    if (core_ep_is_closing(pending_connection->endpoint_id)) {
      TRACE_SERVER("Endpoint #%d is currently closing, waiting before opening", pending_connection->endpoint_id);
      return;
    }
    sl_cpc_system_cmd_property_get(property_get_single_endpoint_state_and_reply_to_pending_open_callback,
                                   (sl_cpc_property_id_t)(PROP_ENDPOINT_STATE_0 + pending_connection->endpoint_id),
                                   5,
                                   100000,
                                   false);
    sl_cpc_system_set_pending_connection(pending_connection->fd_ctrl_data_socket);
    sl_slist_remove(&pending_connections, &pending_connection->node);
    free(pending_connection);
  }
}

#if !defined(UNIT_TESTING)
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

  sl_cpc_system_cmd_noop(system_noop_cmd_callback_t,
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
  cpcd_exchange_buffer_t buffer;
  int fd_connection_socket = private_data->file_descriptor;
  uint8_t endpoint_number = private_data->endpoint_number;

  /* Sanity checks */
  {
    /* We don't deal with system endpoint here*/
    BUG_ON(endpoint_number == 0);

    /* Make sure the connection socket exists */
    BUG_ON(endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor == -1);
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
    data_socket_private_data_list_item_t* new_item;

    /* Allocate resources for this new connection */
    {
      new_item = (data_socket_private_data_list_item_t*) malloc(sizeof(data_socket_private_data_list_item_t));
      FATAL_ON(new_item == NULL);

      sl_slist_push(&endpoints[endpoint_number].data_socket_epoll_private_data, &new_item->node);
    }

    /* Register this new connection's socket to epoll set */
    {
      epoll_private_data_t* private_data = &new_item->data_socket_epoll_private_data;

      private_data->callback = server_process_epoll_fd_ep_data_socket;
      private_data->endpoint_number = endpoint_number;
      private_data->file_descriptor = new_data_socket;

      epoll_register(private_data);
    }
  }

  endpoints[endpoint_number].open_connections++;
  PRINT_INFO("Endpoint socket #%d: Client connected. %d connections", endpoint_number, endpoints[endpoint_number].open_connections);

  /* Tell the core that this endpoint is open */
  core_process_endpoint_change(endpoint_number, SL_CPC_STATE_OPEN);
  TRACE_SERVER("Told core to open ep#%u", endpoint_number);

  /* Acknowledge the user so that they can start using the endpoint */
  buffer.endpoint_number = endpoint_number;
  buffer.type = EXCHANGE_OPEN_ENDPOINT_QUERY;
  ssize_t retval = send(new_data_socket, &buffer, sizeof(cpcd_exchange_buffer_t), 0);
  FATAL_SYSCALL_ON(retval != sizeof(cpcd_exchange_buffer_t));
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
  if (core_get_endpoint_state(endpoint_number) == SL_CPC_STATE_OPEN) {
    core_write(endpoint_number, buffer, buffer_len, 0);
    free(buffer);
  } else {
    free(buffer);
    WARN("User tried to push on endpoint %d but it's not open, state is %d", endpoint_number, core_get_endpoint_state(endpoint_number));
    server_close_endpoint(endpoint_number, false);
  }
}

static void server_handle_client_disconnected(uint8_t endpoint_number)
{
  FATAL_ON(endpoints[endpoint_number].open_connections == 0);

  endpoints[endpoint_number].open_connections--;
  PRINT_INFO("Endpoint socket #%d: Client disconnected. %d connections", endpoint_number, endpoints[endpoint_number].open_connections);

  if (endpoints[endpoint_number].open_connections == 0) {
    TRACE_SERVER("Closing endpoint socket, no more listeners");
    server_close_endpoint(endpoint_number, false);

    if (endpoints[endpoint_number].pending_close == 0) {
      TRACE_SERVER("No pending close on the endpoint, closing it");
      core_close_endpoint(endpoint_number, true, false);
    }
  }
}

static void server_handle_client_closed_ep_connection(int fd_data_socket, uint8_t endpoint_number)
{
  data_socket_private_data_list_item_t* item;
  data_socket_private_data_list_item_t* next_item;

  /* The while loop that follows is the macro SL_SLIST_FOR_EACH_ENTRY exploded to allow
   * for free()ing items during iteration */

  item = SL_SLIST_ENTRY(endpoints[endpoint_number].data_socket_epoll_private_data,
                        data_socket_private_data_list_item_t,
                        node);

  if (item == NULL) {
    FATAL("data connection not found in the linked list of the endpoint");
  }

  while (1) {
    /* Get next item */
    next_item = SL_SLIST_ENTRY((item)->node.node,
                               data_socket_private_data_list_item_t,
                               node);

    /* We are iterating through the linked list of opened connections,
     * check if this iteration is the good one*/
    if (item->data_socket_epoll_private_data.file_descriptor == fd_data_socket) {
      /* Remove the item from the list*/
      sl_slist_remove(&endpoints[endpoint_number].data_socket_epoll_private_data, &item->node);

      /* Properly shutdown and close this socket on our side (it is on the client's side)*/
      int ret = shutdown(fd_data_socket, SHUT_RDWR);
      FATAL_SYSCALL_ON(ret < 0);

      ret = close(fd_data_socket);
      FATAL_SYSCALL_ON(ret < 0);

      /* Inform server and core that the endpoint lost a listener */
      server_handle_client_disconnected(endpoint_number);

      /* data connections items are malloced */
      free(item);
    }

    /* End of list ? */
    item = next_item;
    if (item == NULL) {
      break;
    }
  }
}

static void server_handle_client_closed_ctrl_connection(int fd_data_socket)
{
  ctrl_socket_private_data_list_item_t* item;
  ctrl_socket_private_data_list_item_t* next_item;

  /* The while loop that follows is the macro SL_SLIST_FOR_EACH_ENTRY exploded to allow
   * for free()ing items during iteration */

  item = SL_SLIST_ENTRY(ctrl_connections,
                        ctrl_socket_private_data_list_item_t,
                        node);

  if (item == NULL) {
    FATAL("ctrl data connection not found in the linked list of the ctrl socket");
  }

  while (1) {
    /* Get the next item */
    next_item = SL_SLIST_ENTRY((item)->node.node,
                               ctrl_socket_private_data_list_item_t,
                               node);

    /* We are iterating through the linked list of opened connections,
     * check if this iteration is the good one*/
    if (item->data_socket_epoll_private_data.file_descriptor == fd_data_socket) {
      /* Remove the item from the list*/
      sl_slist_remove(&ctrl_connections, &item->node);

      /* Properly shutdown and close this socket on our side (it is on the client's side)*/
      int ret = shutdown(fd_data_socket, SHUT_RDWR);
      FATAL_SYSCALL_ON(ret < 0);

      ret = close(fd_data_socket);
      FATAL_SYSCALL_ON(ret < 0);

      /* data connections items are malloced */
      free(item);
    }

    /* End of list ? */
    item = next_item;
    if (item == NULL) {
      break;
    }
  }
}

/*
 * This function creates AF_UNIX::SOCK_SEQPACKET named connection socket
 * in /tmp/cpcd/epX.cpcd.sock, adds it to the list of connection sockets and listen
 * to it.
 */
void server_open_endpoint(uint8_t endpoint_number) /* <-- has been made public for system_callback.c */
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
    BUG_ON(endpoints[endpoint_number].data_socket_epoll_private_data != NULL);
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

        nchars = snprintf(name.sun_path, size, "%s/cpcd/%s/ep%d.cpcd.sock", config_socket_folder, config_instance_name, endpoint_number);

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

  TRACE_SERVER("Closing ep#%u", endpoint_number);

  /* Close every open connection on that endpoint (data socket) */
  while (endpoints[endpoint_number].data_socket_epoll_private_data != NULL) {
    data_socket_private_data_list_item_t* item;
    data_sock_i++;

    /* Pop the first element of the list */
    {
      sl_slist_node_t* node = sl_slist_pop(&endpoints[endpoint_number].data_socket_epoll_private_data);

      item = SL_SLIST_ENTRY(node, data_socket_private_data_list_item_t, node);
    }

    /* Unregister the data socket file descriptor from epoll watch list */
    {
      epoll_unregister(&item->data_socket_epoll_private_data);
    }

    /* Close the socket */
    {
      ret = shutdown(item->data_socket_epoll_private_data.file_descriptor, SHUT_RDWR);
      FATAL_SYSCALL_ON(ret < 0);

      ret = close(item->data_socket_epoll_private_data.file_descriptor);
      FATAL_SYSCALL_ON(ret < 0);
    }

    /* Free per-connection allocated sources  */
    {
      /* Unlike connection sockets, which is one per endpoint (and we know there are 255 of them)
       * and statically allocated in the fixed 255 size array at the top of this file, data sockets
       * are dynamically allocated because an arbitrary number of application can decide to connect
       * to an opened endpoint */
      /* Linked list items are malloc'ed, free them */
      free(item);
    }

    TRACE_SERVER("Closed data socket #%u on ep#%u", data_sock_i, endpoint_number);
  }

  /* Close the connection socket */
  {
    int fd_connection_socket = endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor;

    if (fd_connection_socket > 0) {
      /* Unregister the connection socket file descriptor from epoll watch list */
      epoll_unregister(&endpoints[endpoint_number].connection_socket_epoll_private_data);

      /* Close the connection socket */
      ret = shutdown(fd_connection_socket, SHUT_RDWR);
      FATAL_SYSCALL_ON(ret < 0);

      ret = close(fd_connection_socket);
      FATAL_SYSCALL_ON(ret < 0);
    }

    /* Clean its lingering file system socket file */
    {
      /* The connection socket was named and bound to a file system name. Shutting() it down
       * and closing() it doesn't 'delete' its file, it has to be manually unlinked */
      char endpoint_path[108];

      /* Create the endpoint path */
      {
        int nchars;
        const size_t size = sizeof(endpoint_path);

        nchars = snprintf(endpoint_path, size, "%s/cpcd/%s/ep%d.cpcd.sock", config_socket_folder, config_instance_name, endpoint_number);

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
      endpoints[endpoint_number].pending_close = endpoints[endpoint_number].open_connections;
    }
    endpoints[endpoint_number].open_connections = 0;

    TRACE_SERVER("Closed connection socket for ep#%u", endpoint_number);
  }
}

/* Send data to all connected apps on a given endpoint
 *
 * When the server retrieves endoint data from the core, it calls this function to
 * forward the data out of the daemon to all the connected apps.
 */
void server_push_data_to_endpoint(uint8_t endpoint_number, const uint8_t* data, size_t data_len)
{
  data_socket_private_data_list_item_t* item;

  /* Sanity checks */
  {
    /* If we receive data for an endpoint from the core and try to push it to an
     * endpoint socket that is closed (that is, doesn't have its connection socket
     * up), its a bug. Server and core should be coherent */
    BUG_ON(endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor == -1);

    /* Give a warning if we want to push data but no apps are connected to the
     * endpoint. That is, the list of data sockets is empty */
    WARN_ON(endpoints[endpoint_number].data_socket_epoll_private_data == NULL);
  }

  /* Push the buffer's payload to each connected app */
  item = SL_SLIST_ENTRY(endpoints[endpoint_number].data_socket_epoll_private_data,
                        data_socket_private_data_list_item_t,
                        node);

  /* Iterate through all data sockets for that endpoint */
  while (item != NULL) {
    ssize_t wc = send(item->data_socket_epoll_private_data.file_descriptor,
                      data,
                      data_len,
                      MSG_DONTWAIT);
    if (wc < 0) {
      TRACE_SERVER("send() failed with %s", ERRNO_CODENAME[errno]);
    }

    /* Close unresponsive sockets */
    if (wc < 0 && (errno == EAGAIN || errno == EPIPE || errno == ECONNRESET)) {
      WARN("Unresponsive data socket on endpoint_number %d, closing", endpoint_number);

      /* Unregister the data socket file descriptor from epoll watch list */
      epoll_unregister(&item->data_socket_epoll_private_data);

      /* Properly shutdown and close this socket on our side */
      int ret = shutdown(item->data_socket_epoll_private_data.file_descriptor, SHUT_RDWR);
      FATAL_SYSCALL_ON(ret < 0);

      ret = close(item->data_socket_epoll_private_data.file_descriptor);
      FATAL_SYSCALL_ON(ret < 0);

      /* Remove the item from the list*/
      sl_slist_remove(&endpoints[endpoint_number].data_socket_epoll_private_data, &item->node);

      /* data connections items are malloced */
      free(item);

      FATAL_ON(endpoints[endpoint_number].open_connections == 0);

      endpoints[endpoint_number].open_connections--;
      PRINT_INFO("Endpoint socket #%d: Client disconnected. %d connections", endpoint_number, endpoints[endpoint_number].open_connections);

      if (endpoints[endpoint_number].open_connections == 0) {
        TRACE_SERVER("Endpoint was unresponsive, closing endpoint socket, no more listeners");
        server_close_endpoint(endpoint_number, false);
        core_close_endpoint(endpoint_number, true, false);
        return;
      }

      /* Get the next data socket for that endpoint*/
      item = SL_SLIST_ENTRY(endpoints[endpoint_number].data_socket_epoll_private_data,
                            data_socket_private_data_list_item_t,
                            node);
    } else {
      /* The data should have been be completely written to the socket */
      FATAL_SYSCALL_ON(wc < 0);
      FATAL_ON((size_t)wc != data_len);

      /* Get the next data socket for that endpoint*/
      item = SL_SLIST_ENTRY((item)->node.node,
                            data_socket_private_data_list_item_t,
                            node);
    }
  }
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
    buffer = (uint8_t*) malloc((size_t)PAD_TO_8_BYTES(datagram_length));
    FATAL_ON(buffer == NULL);
  }

  /* Fetch the data from the data socket */
  {
    rc = recv(fd_data_socket, buffer, (size_t)datagram_length, 0);
    if (rc < 0) {
      TRACE_SERVER("recv() failed with %s", ERRNO_CODENAME[errno]);
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
  return endpoints[endpoint_number].open_connections == 0;
}

void server_notify_connected_libs_of_secondary_reset(void)
{
  ctrl_socket_private_data_list_item_t* item;

  SL_SLIST_FOR_EACH_ENTRY(ctrl_connections,
                          item,
                          ctrl_socket_private_data_list_item_t,
                          node){
    if (item->pid != getpid()) {
      if (item->pid > 1) {
        kill(item->pid, SIGUSR1);
      } else {
        BUG("Connected library's pid it not set");
      }
    }
  }
}
