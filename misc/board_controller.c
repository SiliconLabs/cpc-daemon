/***************************************************************************/ /**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Board Controller
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cpcd/board_controller.h"
#include "cpcd/logging.h"

int board_controller_parse_wstk_config(const char *buffer,
                                       unsigned int *baudrate,
                                       bool *flowcontrol)
{
  if (!buffer || !baudrate || !flowcontrol) {
    return -1;
  }

  // Extract baudrate
  {
    const char *label_pos = strstr(buffer, "Active port speed");
    if (!label_pos) {
      return -1;
    }

    // sscanf whitespace matches any amount of whitespace (including zero)
    if (sscanf(label_pos, "Active port speed : %u", baudrate) != 1) {
      return -1;
    }
  }

  // Extract flow control
  {
    const char *label_pos = strstr(buffer, "Actual handshake");
    if (!label_pos) {
      return -1;
    }

    char handshake_value[32] = { 0 };
    // sscanf whitespace matches any amount of whitespace (including zero)
    // Use field width to prevent buffer overflow (31 chars + null terminator)
    if (sscanf(label_pos, "Actual handshake : %31s", handshake_value) != 1) {
      return -1;
    }
    *flowcontrol = (strcmp(handshake_value, "rtscts") == 0);
  }

  return 0;
}

void board_controller_get_config_vcom(const char *ip_address,
                                      unsigned int *baudrate,
                                      bool *flowcontrol)
{
  int socket_handle;
  struct sockaddr_in server;
  const unsigned short telnet_port = 4902;
  char recv_buf[256]               = { 0 };

  socket_handle = socket(AF_INET, SOCK_STREAM, 0);
  FATAL_SYSCALL_ON(socket_handle == -1);

  server.sin_family      = AF_INET;
  server.sin_port        = htons(telnet_port);
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

  // Parse the WSTK configuration from the buffer
  if (board_controller_parse_wstk_config(recv_buf, baudrate, flowcontrol) != 0) {
    close(socket_handle);
    FATAL("Cannot parse board controller response");
  }

  close(socket_handle);
}
