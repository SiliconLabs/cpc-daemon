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
#include <unistd.h>

#include "log.h"
#include "server.h"
#include "server_core.h"
#include "utils.h"
#include "sl_slist.h"
#include "cpc_interface.h"
#include "core.h"
#include "config.h"
#include "system/system.h"
#include "system_callbacks.h"
#include "server_internal.h"
#include "epoll.h"
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

/* List to keep track of every connected library instance on /run/cpc/ctrl.cpcd.sock */
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

static void server_handle_client_closed_from_ctrl(uint8_t endpoint_number);
static void server_handle_client_closed_ep_connection(int fd_data_socket, uint8_t endpoint_number);
static void server_handle_client_closed_ctrl_connection(int fd_data_socket);
static void server_pull_data_from_data_socket(int fd_data_socket, uint8_t** buffer, size_t* buffer_len);

/*******************************************************************************
 **************************   IMPLEMENTATION    ********************************
 ******************************************************************************/
void server_init(void)
{
#if !defined(UNIT_TESTING)
  int fd_timer_noop;
#endif

  int ret;

  /* Create the control socket /run/cpc/ctrl.cpcd.sock and start listening for connections */
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
      snprintf(name.sun_path, sizeof(name.sun_path) - 1, "%s/cpcd/ctrl.cpcd.sock", config_socket_folder);

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
      fd_timer_noop = timerfd_create(CLOCK_MONOTONIC, 0);
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
}

/*
 * This function is called when we know we can pull from the core.
 * The core sends a flexible 'cpc_interface_buffer_t' struct.
 * Retrieve it and dispatch it in function of its 'type'.
 */
void server_process_core(cpc_interface_buffer_t* interface_buffer, size_t interface_buffer_size)
{
  switch (interface_buffer->type) {
    case SERVER_CORE_EXCHANGE_WRITE_COMPLETED:

      BUG_ON(interface_buffer_size != sizeof(cpc_interface_buffer_t) + sizeof(sl_status_t));

      sl_status_t status = *(sl_status_t*)interface_buffer->payload;

      if (status == SL_STATUS_OK) {
        TRACE_SERVER("Write Complete on ep#%d", interface_buffer->endpoint_number);
      } else {
        TRACE_SERVER("Write NOT complete on ep#%d", interface_buffer->endpoint_number);
      }
      break;

    default:
      BUG();
      break;
  }
}

void server_expect_close(uint8_t endpoint_number)
{
  FATAL_ON(endpoint_number == 0); // Can't expect to close the system endpoint
  endpoints[endpoint_number].pending_close++;
}

static void server_process_epoll_fd_ctrl_connection_socket(epoll_private_data_t *private_data)
{
  (void) private_data;
  int new_data_socket;

  /* Accept the new ctrl connection for that client */
  new_data_socket = accept(fd_socket_ctrl, NULL, NULL);
  FATAL_SYSCALL_ON(new_data_socket < 0);

  /* Add the new data socket in the list of data sockets for ctrl */
  {
    ctrl_socket_private_data_list_item_t* new_item;

    /* Allocate resources for this new connection */
    {
      new_item = (ctrl_socket_private_data_list_item_t*) malloc(sizeof(ctrl_socket_private_data_list_item_t));

      FATAL_ON(new_item == NULL);

      new_item->pid = -1;
    }

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
  cpc_interface_buffer_t *interface_buffer;

  /* Check if the event is about the client closing the connection */
  {
    int length;

    int retval = ioctl(fd_ctrl_data_socket, FIONREAD, &length);

    FATAL_SYSCALL_ON(retval < 0);

    if (length == 0) {
      server_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
      return;
    }
  }

  /* Retrieve the payload from the endpoint data connection */
  server_pull_data_from_data_socket(fd_ctrl_data_socket, &buffer, &buffer_len);
  FATAL_ON(buffer_len < sizeof(cpc_interface_buffer_t));
  interface_buffer = (cpc_interface_buffer_t *)buffer;

  switch (interface_buffer->type) {
    case EXCHANGE_ENDPOINT_STATUS_QUERY:
      /* Client requested an endpoint status */
    {
      cpc_endpoint_state_t ep_state;
      TRACE_SERVER("Received an endpoint status query");

      BUG_ON(buffer_len != sizeof(cpc_interface_buffer_t) + sizeof(cpc_endpoint_state_t));

      ep_state = core_get_endpoint_state(interface_buffer->endpoint_number);

      memcpy(interface_buffer->payload, &ep_state, sizeof(cpc_endpoint_state_t));

      ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

      FATAL_SYSCALL_ON(ret < 0);
      FATAL_ON((size_t)ret != sizeof(cpc_interface_buffer_t) + sizeof(cpc_endpoint_state_t));
    }
    break;

    case EXCHANGE_MAX_WRITE_SIZE_QUERY:
      /* Client requested maximum write size */
    {
      TRACE_SERVER("Received an maximum write size query");

      BUG_ON(buffer_len != sizeof(cpc_interface_buffer_t) + sizeof(size_t));
      size_t rx_capability = (size_t)server_core_get_secondary_rx_capability();
      memcpy(interface_buffer->payload, &rx_capability, sizeof(size_t));

      ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

      FATAL_SYSCALL_ON(ret < 0);
      FATAL_ON((size_t)ret != sizeof(cpc_interface_buffer_t) + sizeof(size_t));
    }
    break;

    case EXCHANGE_VERSION_QUERY:
      /* Client requested the version of the daemon*/
    {
      TRACE_SERVER("Received a version query");

      BUG_ON(buffer_len != sizeof(cpc_interface_buffer_t) + sizeof(PROJECT_VER));
      memcpy(interface_buffer->payload, PROJECT_VER, sizeof(PROJECT_VER));

      ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

      FATAL_SYSCALL_ON(ret < 0);
      FATAL_ON((size_t)ret != sizeof(cpc_interface_buffer_t) + sizeof(PROJECT_VER));
    }
    break;

    case EXCHANGE_OPEN_ENDPOINT_QUERY:
      /* Client requested to open an endpoint socket*/
    {
      TRACE_SERVER("Received an endpoint open query");

      BUG_ON(buffer_len != sizeof(cpc_interface_buffer_t) + sizeof(bool));

      /* Add this connection to the pending connections list, we need to check the secondary if the endpoint is open */
      /* This will be done in the server_process_pending_connections function */
      pending_connection_list_item_t *pending_connection = malloc(sizeof(pending_connection_list_item_t));
      pending_connection->endpoint_id = interface_buffer->endpoint_number;
      pending_connection->fd_ctrl_data_socket = fd_ctrl_data_socket;
      sl_slist_push(&pending_connections, &pending_connection->node);
    }
    break;

    case EXCHANGE_CLOSE_ENDPOINT_QUERY:
    {
      server_handle_client_closed_from_ctrl(interface_buffer->endpoint_number);
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

  if (pending_connection != NULL) {
    sl_cpc_system_cmd_property_get(property_get_single_endpoint_state_and_reply_to_pending_open_callback,
                                   (sl_cpc_property_id_t)(PROP_ENDPOINT_STATE_0 + pending_connection->endpoint_id),
                                   5, //TODO 5 retries
                                   100000); //TODO 100 ms
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
  int new_data_socket;
  cpc_interface_buffer_t buffer;
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

  /* Add the new data socket in the list of data sockets for that endpoint */
  {
    data_socket_private_data_list_item_t* new_item;

    /* Allocate resources for this new connection */
    {
      new_item = (data_socket_private_data_list_item_t*) malloc(sizeof(data_socket_private_data_list_item_t));
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

  /* Tell the core that this endpoint is open */
  endpoints[endpoint_number].open_connections++;
  core_process_endpoint_change(endpoint_number, SL_CPC_STATE_OPEN);
  TRACE_SERVER("Told core to open ep#%u\n", endpoint_number);

  /* Acknowledge the user so that they can start using the endpoint */
  buffer.endpoint_number = endpoint_number;
  buffer.type = EXCHANGE_OPEN_ENDPOINT_QUERY;
  ssize_t retval = send(new_data_socket, &buffer, sizeof(cpc_interface_buffer_t), 0);
  FATAL_SYSCALL_ON(retval != sizeof(cpc_interface_buffer_t));
}

static void server_process_epoll_fd_ep_data_socket(epoll_private_data_t *private_data)
{
  uint8_t* buffer;
  size_t buffer_len;
  int fd_data_socket = private_data->file_descriptor;
  uint8_t endpoint_number = private_data->endpoint_number;

  if (core_ep_is_busy(endpoint_number)) {
    return;
  }

  /* Check if the event is about the client closing the connection */
  {
    int length;

    int retval = ioctl(fd_data_socket, FIONREAD, &length);

    FATAL_SYSCALL_ON(retval < 0);

    if (length == 0) {
      server_handle_client_closed_ep_connection(fd_data_socket, endpoint_number);
      return;
    }
  }

  /* The event is about rx data */

  /* Retrieve the payload from the endpoint data connection */
  server_pull_data_from_data_socket(fd_data_socket, &buffer, &buffer_len);

  /* Send the data to the core */
  if (core_get_endpoint_state(endpoint_number) == SL_CPC_STATE_OPEN) {
    core_write(endpoint_number, buffer, buffer_len, 0);
  } else {
    free(buffer);
    WARN("User tried to push on endpoint %d but it's not open, state is %d", endpoint_number, core_get_endpoint_state(endpoint_number));
    server_close_endpoint(endpoint_number);
  }
}

static void server_handle_client_closed_from_ctrl(uint8_t endpoint_number)
{
  if (endpoints[endpoint_number].open_connections != 0) {
    endpoints[endpoint_number].open_connections--;

    if (endpoints[endpoint_number].open_connections == 0) {
      TRACE_SERVER("Closing endpoint socket, no more listeners");
      server_close_endpoint(endpoint_number);
      core_close_endpoint(endpoint_number, true);
    }
  } else {
    core_close_endpoint(endpoint_number, true);
  }

  if (endpoints[endpoint_number].pending_close > 0) {
    endpoints[endpoint_number].pending_close--;
  }
}

static void server_handle_client_closed_ep_connection(int fd_data_socket, uint8_t endpoint_number)
{
  data_socket_private_data_list_item_t* item;

  /* The while loop that follows is the macro SL_SLIST_FOR_EACH_ENTRY exploded to allow
   * for free()ing items during iteration */

  item = SL_SLIST_ENTRY(endpoints[endpoint_number].data_socket_epoll_private_data,
                        data_socket_private_data_list_item_t,
                        node);

  if (item == NULL) {
    FATAL("data connection not found in the linked list of the endpoint");
  }

  while (1) {
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

      /* data connections items are malloced */
      free(item);

      /* Get new item */
      item = SL_SLIST_ENTRY(endpoints[endpoint_number].data_socket_epoll_private_data,
                            data_socket_private_data_list_item_t,
                            node);
    } else {
      /* Get next item */
      item = SL_SLIST_ENTRY(endpoints[endpoint_number].data_socket_epoll_private_data->node,
                            data_socket_private_data_list_item_t,
                            node);
    }

    /* End of list ? */
    if (item == NULL) {
      break;
    }
  }
}

static void server_handle_client_closed_ctrl_connection(int fd_data_socket)
{
  uint8_t i;
  ctrl_socket_private_data_list_item_t* item;

  /* The while loop that follows is the macro SL_SLIST_FOR_EACH_ENTRY exploded to allow
   * for free()ing items during iteration */

  item = SL_SLIST_ENTRY(ctrl_connections,
                        ctrl_socket_private_data_list_item_t,
                        node);

  /* If we are here, a client process closed or it crashed */
  for (i = 1; i < 255; i++) {
    if (endpoints[i].pending_close > 0) {
      endpoints[i].pending_close--;
      if (endpoints[i].pending_close == 0) {
        core_close_endpoint(i, true);
      }
    }
  }

  if (item == NULL) {
    FATAL("ctrl data connection not found in the linked list of the ctrl socket");
  }

  while (1) {
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

      /* Get new item */
      item = SL_SLIST_ENTRY(ctrl_connections,
                            ctrl_socket_private_data_list_item_t,
                            node);
    } else {
      /* Get next item */
      item = SL_SLIST_ENTRY(ctrl_connections->node,
                            ctrl_socket_private_data_list_item_t,
                            node);
    }

    /* End of list ? */
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
      snprintf(name.sun_path, sizeof(name.sun_path) - 1, "%s/cpcd/ep%d.cpcd.sock", config_socket_folder, endpoint_number);

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

  TRACE_SERVER("Opened ep#%u (listening on connection socket /run/cpc/ep%u.cpcd.sock\n", endpoint_number, endpoint_number);
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
void server_close_endpoint(uint8_t endpoint_number)
{
  size_t data_sock_i = 0;
  int ret;

  TRACE_SERVER("Closing ep#%u\n", endpoint_number);

  /* Sanity check */
  {
    /* System endpoint is not like the others, if we create a socket for it, there's a bug */
    BUG_ON(endpoint_number == 0);

    if (endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor == -1) {
      return; // Endpoint was previously closed
    }
  }

  /* Close every open connection on that endpoint (data socket) */
  while (endpoints[endpoint_number].data_socket_epoll_private_data != NULL) {
    data_socket_private_data_list_item_t* item;
    data_sock_i++;

    /* Pop the first element of the list*/
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

    TRACE_SERVER("Closed data socket #%u on ep#%u\n", data_sock_i, endpoint_number);
  }

  /* Close the connection socket */
  {
    int fd_connection_socket = endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor;

    /* Unregister the connection socket file descriptor from epoll watch list */
    {
      epoll_unregister(&endpoints[endpoint_number].connection_socket_epoll_private_data);
    }

    /* Close the connection socket */
    {
      ret = shutdown(fd_connection_socket, SHUT_RDWR);
      FATAL_SYSCALL_ON(ret < 0);

      ret = close(fd_connection_socket);
      FATAL_SYSCALL_ON(ret < 0);
    }

    /* Clean its lingering file system socket file */
    {
      /* The connection socket was named and bound to a file system name. Shutting() it down
       * and closing() it doesn't 'delete' its file, it has to be manually unlinked */
      char name[108];
      snprintf(name, sizeof(name) - 1, "%s/cpcd/ep%d.cpcd.sock", config_socket_folder, endpoint_number);
      ret = unlink(name);
      FATAL_SYSCALL_ON(ret < 0);
    }

    /* Set the connection socket file descriptor to -1 to signify that the endpoint is closed */
    endpoints[endpoint_number].connection_socket_epoll_private_data.file_descriptor = -1;

    TRACE_SERVER("Closed connection socket on ep#%u\n", endpoint_number);
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
    ssize_t retval = send(item->data_socket_epoll_private_data.file_descriptor,
                          data,
                          data_len,
                          MSG_DONTWAIT);

    /* Close unresponsive sockets */
    if (retval == -1 && errno == EAGAIN) {
      WARN("Unresponsive data socket on endpoint_number %d, closing", endpoint_number);
      /* Properly shutdown and close this socket on our side */
      int ret = shutdown(item->data_socket_epoll_private_data.file_descriptor, SHUT_RDWR);
      FATAL_SYSCALL_ON(ret < 0);

      ret = close(item->data_socket_epoll_private_data.file_descriptor);
      FATAL_SYSCALL_ON(ret < 0);

      /* Remove the item from the list*/
      sl_slist_remove(&endpoints[endpoint_number].data_socket_epoll_private_data, &item->node);

      /* data connections items are malloced */
      free(item);

      endpoints[endpoint_number].open_connections--;

      if (endpoints[endpoint_number].open_connections == 0) {
        TRACE_SERVER("Endpoint was unresponsive, closing endpoint socket, no more listeners");
        server_close_endpoint(endpoint_number);
        core_close_endpoint(endpoint_number, true);
        return;
      }

      /* Get the next data socket for that endpoint*/
      item = SL_SLIST_ENTRY(endpoints[endpoint_number].data_socket_epoll_private_data,
                            data_socket_private_data_list_item_t,
                            node);
    } else {
      /* The data should have been be completely written to the socket */
      FATAL_SYSCALL_ON(retval < 0);
      FATAL_ON((size_t)retval != data_len);

      /* Get the next data socket for that endpoint*/
      item = SL_SLIST_ENTRY((item)->node.node,
                            data_socket_private_data_list_item_t,
                            node);
    }
  }
}

static void server_pull_data_from_data_socket(int fd_data_socket, uint8_t** buffer, size_t* buffer_len)
{
  int datagram_length;
  ssize_t ret;

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
    *buffer = (uint8_t*) malloc((size_t)datagram_length);
    FATAL_ON(*buffer == NULL);
  }

  /* Fetch the data from the data socket */
  {
    ret = recv(fd_data_socket, *buffer, (size_t)datagram_length, 0);

    FATAL_SYSCALL_ON(ret < 0);
  }

  *buffer_len = (size_t)ret;
}

bool server_listener_list_empty(uint8_t endpoint_number)
{
  if (endpoints[endpoint_number].open_connections == 0) {
    return true;
  } else {
    return false;
  }
}

void server_notify_connected_libs_of_secondary_reset(void)
{
  ctrl_socket_private_data_list_item_t* item;

  /* Push the buffer's payload to each connected app */
  SL_SLIST_FOR_EACH_ENTRY(ctrl_connections,
                          item,
                          ctrl_socket_private_data_list_item_t,
                          node){
    if (item->pid > 1) {
      kill(item->pid, SIGUSR1);
    } else {
      WARN("Connected library's pid it not set");
    }
  }
}
