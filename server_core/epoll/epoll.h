/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Poll
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

#ifndef EPOLL_H
#define EPOLL_H

#include "stdint.h"
#include <sys/epoll.h>

//forward declaration for interdependency
struct epoll_private_data;

typedef struct epoll_private_data epoll_private_data_t;

typedef void (*epoll_callback_t)(epoll_private_data_t *private_data);

struct epoll_private_data{
  epoll_callback_t callback;
  int file_descriptor;
  uint8_t endpoint_number;
};

void epoll_init(void);

void epoll_register(epoll_private_data_t *private_data);

void epoll_unregister(epoll_private_data_t *private_data);

void epoll_unwatch(epoll_private_data_t *private_data);

void epoll_watch_back(uint8_t endpoint_number);

size_t epoll_wait_for_event(struct epoll_event events[], size_t max_event_number);

#endif //EPOLL_H
