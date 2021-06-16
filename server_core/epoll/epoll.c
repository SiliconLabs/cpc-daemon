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
#include "log.h"
#include "core.h"
#include "server.h"

#include <sys/epoll.h>
#include <string.h>
#include <errno.h>

static int fd_epoll;

void epoll_init(void)
{
  /* Create the epoll set */
  {
    fd_epoll = epoll_create1(0);
    FATAL_SYSCALL_ON(fd_epoll < 0);
  }
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

  FATAL_ON(private_data == NULL);
  FATAL_ON(private_data->callback == NULL);
  FATAL_ON(private_data->file_descriptor < 1);

  ret = epoll_ctl(fd_epoll, EPOLL_CTL_DEL, private_data->file_descriptor, NULL);
  FATAL_SYSCALL_ON(ret < 0);
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
