/***************************************************************************//**
 * @file
 * @brief Interface for driver sdio to interact with netlink
 *******************************************************************************
 * # License
 * <b>Copyright 2024 Silicon Laboratories Inc. www.silabs.com</b>
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

#include <pthread.h>
#include <stdio.h>

#include "cpcd/logging.h"

#include "nl_socket.h"
#include "nl_sdio_interface.h"

int sl_nl_sdio_init(void)
{
  pthread_t thread1;
  sli_linux_driver_cb_t *driver_cbPtr = &sli_linux_driver_app_cb;
  int32_t retval;

  // Open a socket for issueing ioctls
  driver_cbPtr->ioctl_sd = socket(AF_INET, SOCK_DGRAM, 0);
  FATAL_SYSCALL_ON(driver_cbPtr->ioctl_sd < 0);

  // Open a netlink socket
  retval = sli_nl_socket_init();
  if (retval == -1) {
    return NETLINK_SDIO_ERROR;
  }

  sli_fill_genl_nl_hdrs_for_cmd(&sli_linux_driver_app_cb);
  retval = pthread_create(&thread1, NULL, RecvThreadBody, NULL);
  FATAL_ON(retval != 0);

  retval = pthread_setname_np(thread1, "Recv Thread");
  FATAL_ON(retval != 0);
  return 0;
}

ssize_t sli_execute_cmd(const uint8_t *desc, const uint8_t *payload, size_t payload_size)
{
  ssize_t retval;
  uint8_t *cmd_buff;

  cmd_buff = sli_alloc_and_init_cmdbuff(desc, payload, payload_size);
  retval = sli_send_usr_cmd(cmd_buff, GET_SEND_LENGTH(cmd_buff));
  if (retval < 0) {
    retval = NETLINK_SDIO_ERROR;
  }

  // Free the command buffer
  free(cmd_buff);
  return retval;
}

ssize_t nl_sdio_interface_register_irq(void)
{
  /* set unblock interrupt frame */
  uint8_t sli_frameRegisterIrq[] = { 0x00, 0xEE, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

  return sli_execute_cmd((uint8_t *)&sli_frameRegisterIrq, NULL, 0);
}
