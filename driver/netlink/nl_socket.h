/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - NETLINK socket
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

#ifndef NL_SOCKET_H
#define NL_SOCKET_H

#include <errno.h>
#include <linux/genetlink.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "nl_sdio_interface.h"

/*
 * Generic macros for dealing with netlink sockets. Might be duplicated
 * elsewhere. It is recommended that commercial grade applications use
 * libnl or libnetlink and use the interfaces provided by the library
 */
#define GENLMSG_DATA(glh)  (((void *)((char *)NLMSG_DATA(glh) + GENL_HDRLEN)))
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define SLI_NLA_ALIGN(len)    ((int)((len) + NLA_ALIGNTO - 1) & ~(int)(NLA_ALIGNTO - 1))
#define SLI_NLA_HDRLEN        (__u16)((int) SLI_NLA_ALIGN(sizeof(struct nlattr)))
#define NLA_DATA(na)  ((void *)((char*)(na) + SLI_NLA_HDRLEN))
#define MAX_RCV_SIZE  4100
#define SLI_NL_HEAD_SIZE         (sizeof(struct nlmsghdr) + sizeof(struct genlmsghdr) + sizeof(struct nlattr))
#define SLI_STATUS_OFFSET         12
#define SLI_TWOBYTE_STATUS_OFFSET 12
#define SLI_RSP_TYPE_OFFSET       2
#define GET_SEND_LENGTH(a) ((uint16_t)(*(uint32_t *)(a)))

#define NETLINK_SDIO_ERROR -1

// User to Kernel Update Types
enum {
  MODULE_POWER_CYCLE               = 0x01,
  UPDATE_JOIN_DONE                 = 0x02,
  PS_CONTINUE                      = 0x03,
  WKP_FROM_HOST                    = 0x04,
};

// Netlink Packet Header
typedef struct {
  struct nlmsghdr netlink_msghdr;        // from netlink library
  struct genlmsghdr genl_netlink_msghdr; // from netlink library
} sli_nlPkt_t;

uint8_t *sli_alloc_and_init_cmdbuff(const uint8_t *Desc, const uint8_t *payload, size_t payload_size);
ssize_t sli_send_usr_cmd(uint8_t *buff, uint16_t bufLen);
int32_t sli_nl_socket_init(void);
void sli_fill_genl_nl_hdrs_for_cmd(sli_linux_driver_cb_t *driver_cb);

#endif // NL_SOCKET_H
