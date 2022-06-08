/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Poll
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

#include "epoll.h"
#include "misc/logging.h"
#include "misc/sl_slist.h"
#include "server_core/core/core.h"
#include "server_core/server/server.h"

#include <sys/epoll.h>
#include <string.h>
#include <errno.h>

typedef struct {
  sl_slist_node_t node;
  struct epoll_private_data* unregistered_epoll_private_data;
}unwatched_endpoint_list_item_t;

/* List to keep track of every connected library instance over the control socket */
static sl_slist_node_t *unwatched_endpoint_list;

static int fd_epoll;

void epoll_init(void)
{
  /* Create the epoll set */
  {
    fd_epoll = epoll_create1(EPOLL_CLOEXEC);
    FATAL_SYSCALL_ON(fd_epoll < 0);
  }

  sl_slist_init(&unwatched_endpoint_list);
}

void epoll_register(epoll_private_data_t *private_data)
{
  struct epoll_event event = {};
  int ret;

  FATAL_ON(private_data == NULL);
  FATAL_ON(private_data->callback == NULL);
  FATAL_ON(private_data->file_descriptor < 1);

  event.events = EPOLLIN; /* Level-triggered read() availability */
  event.data.ptr = private_data;

  ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, private_data->file_descriptor, &event);
  FATAL_SYSCALL_ON(ret < 0);
}

void epoll_unregister(epoll_private_data_t *private_data)
{
  int ret;
  unwatched_endpoint_list_item_t* item;

  FATAL_ON(private_data == NULL);
  FATAL_ON(private_data->callback == NULL);
  FATAL_ON(private_data->file_descriptor < 1);

  /* Before unregistering, check if this private data if for an endpoint
   * that was previously unwatched. If so, delete it from the unwatch list
   * but don't call epoll_ctl::EPOLL_CTL_DEL on it since it was already deleted */
  SL_SLIST_FOR_EACH_ENTRY(unwatched_endpoint_list,
                          item,
                          unwatched_endpoint_list_item_t,
                          node){
    if (private_data == item->unregistered_epoll_private_data) {
      sl_slist_remove(&unwatched_endpoint_list, &item->node);
      free(item);
      return;
    }
  }

  ret = epoll_ctl(fd_epoll, EPOLL_CTL_DEL, private_data->file_descriptor, NULL);

  FATAL_SYSCALL_ON(ret < 0);
}

void epoll_unwatch(epoll_private_data_t *private_data)
{
  epoll_unregister(private_data);

  unwatched_endpoint_list_item_t *item = malloc(sizeof(unwatched_endpoint_list_item_t));
  FATAL_ON(item == NULL);

  item->unregistered_epoll_private_data = private_data;

  sl_slist_push(&unwatched_endpoint_list, &item->node);
}

void epoll_watch_back(uint8_t endpoint_number)
{
  unwatched_endpoint_list_item_t* item;

  /* More than one library connection can exist for one endpoint. When watching back for an
   * endpoint, we want to go through all the connections and watch them back */

  sl_slist_node_t *item_node = unwatched_endpoint_list;
  while (1) {
    item = SL_SLIST_ENTRY(item_node,
                          unwatched_endpoint_list_item_t,
                          node);
    if (item == NULL) {
      break;
    }
    item_node = item_node->node;
    if (endpoint_number == item->unregistered_epoll_private_data->endpoint_number) {
      epoll_register(item->unregistered_epoll_private_data);
      sl_slist_remove(&unwatched_endpoint_list, &item->node);
      free(item);
    }
  }
}

size_t epoll_wait_for_event(struct epoll_event events[], size_t max_event_number)
{
  int event_count;

  do {
    event_count = epoll_wait(fd_epoll, events, (int) max_event_number, -1);
  } while ((event_count == -1) && (errno == EINTR));

  FATAL_SYSCALL_ON(event_count < 0);

  /* Timeouts should not occur */
  FATAL_ON(event_count == 0);

  return (size_t)event_count;
}
