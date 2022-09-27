/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Board Controller
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
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "misc/board_controller.h"
#include "misc/logging.h"

void board_controller_get_config_vcom(const char *ip_address, unsigned int *baudrate, bool *flowcontrol)
{
  int socket_handle;
  struct sockaddr_in server;
  const unsigned short telnet_port = 4902;
  char recv_buf[256] = { 0 };

  socket_handle = socket(AF_INET, SOCK_STREAM, 0);
  FATAL_SYSCALL_ON(socket_handle == -1);

  server.sin_family = AF_INET;
  server.sin_port = htons(telnet_port);
  server.sin_addr.s_addr = inet_addr(ip_address);
  if (connect(socket_handle, (const struct sockaddr *)&server, sizeof(server)) < 0) {
    close(socket_handle);
    FATAL("Cannot connect to board controller");
  }

  // Flush previous buffer
  recv(socket_handle, recv_buf, sizeof(recv_buf), MSG_DONTWAIT);

  // Get serial vcom config
  {
    const char *serial_vcom = "serial vcom\r";
    if (send(socket_handle, serial_vcom, strlen(serial_vcom), 0) < 0) {
      close(socket_handle);
      FATAL("Cannot send to board controller");
    }
    sleep(1);
    recv(socket_handle, recv_buf, sizeof(recv_buf), MSG_DONTWAIT);
  }

  // Extract baudrate
  {
    char *endptr;
    const char *active_port_speed = "Active port speed  : ";
    const char *speed_begin = strstr(recv_buf, active_port_speed);
    if (!speed_begin) {
      close(socket_handle);
      FATAL_ON(speed_begin == NULL);
    }

    char *speed_end = strstr(speed_begin, "\r");
    if (!speed_end) {
      close(socket_handle);
      FATAL_ON(speed_end == NULL);
    }
    *speed_end = '\0';
    *baudrate = (unsigned int)strtol(speed_begin + strlen(active_port_speed), &endptr, 10);
    *speed_end = '\r';
  }

  // Extract flow control
  {
    const char *actual_handshake = "Actual handshake   : ";
    const char *flowcontrol_begin = strstr(recv_buf, actual_handshake);
    if (!flowcontrol_begin) {
      close(socket_handle);
      FATAL_ON(flowcontrol_begin == NULL);
    }

    char *flowcontrol_end = strstr(flowcontrol_begin, "\r");
    if (!flowcontrol_end) {
      close(socket_handle);
      FATAL_ON(flowcontrol_end == NULL);
    }
    *flowcontrol_end = '\0';
    *flowcontrol = strcmp(flowcontrol_begin + strlen(actual_handshake), "rtscts") == 0;
    *flowcontrol_end = '\r';
  }

  close(socket_handle);
}
