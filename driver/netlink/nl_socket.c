/***************************************************************************/ /**
 * @file
 * @brief SDIO, NETLINK socket init, related functions and necessary functions
 * to read the response from kernel and to handle that response
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

#include "cpcd/logging.h"

#include "server_core/core/crc.h"
#include "server_core/core/hdlc.h"

#include "nl_sdio_interface.h"
#include "nl_socket.h"

#define WLAN_PORT_ID 0x1111

sli_linux_driver_cb_t sli_linux_driver_app_cb;

static ssize_t sli_sendto_fd(int socket_fd, const uint8_t *buf, size_t bufLen);
static uint16_t sli_get_family_id(int socket_fdd);
static int sli_create_nl_socket(int32_t protocol, int32_t groups);

int32_t sli_nl_socket_init(void)
{
  sli_linux_driver_cb_t *driver_cbPtr = &sli_linux_driver_app_cb;

  driver_cbPtr->nl_sd = sli_create_nl_socket(NETLINK_GENERIC, 0);
  if (driver_cbPtr->nl_sd < 0) {
    return NETLINK_SDIO_ERROR;
  }

  driver_cbPtr->family_id = sli_get_family_id(driver_cbPtr->nl_sd);
  return 0;
}

void sli_fill_genl_nl_hdrs_for_cmd(sli_linux_driver_cb_t *driver_cb)
{
  sli_nlPkt_t *req;
  req = (sli_nlPkt_t *)(driver_cb->sli_glbl_genl_nl_hdr);

  // Send command needed
  req->netlink_msghdr.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  req->netlink_msghdr.nlmsg_type = driver_cb->family_id;
  req->netlink_msghdr.nlmsg_flags = NLM_F_REQUEST;
  req->netlink_msghdr.nlmsg_seq = 60;
  req->netlink_msghdr.nlmsg_pid = (uint32_t)getpid();
  req->genl_netlink_msghdr.cmd = 1;
}

uint8_t *sli_alloc_and_init_cmdbuff(const uint8_t *Desc, const uint8_t *payload, size_t payload_size)
{
  uint8_t *cmd_buff;
  sli_nlPkt_t *req;
  struct nlattr *na;

  cmd_buff =
    malloc(payload_size + (size_t)SLI_CPC_HDLC_HEADER_RAW_SIZE
           + SLI_NL_HEAD_SIZE);
  FATAL_ON(cmd_buff == NULL);

  req = (sli_nlPkt_t *)cmd_buff;

  memcpy(cmd_buff, sli_linux_driver_app_cb.sli_glbl_genl_nl_hdr,
         SLI_NL_HEAD_SIZE - sizeof(struct nlattr));
  // compose message
  na = (struct nlattr *)GENLMSG_DATA(cmd_buff);
  na->nla_type = 1; // DOC_EXMPL_A_MSG

  size_t message_len = payload_size + SLI_CPC_HDLC_HEADER_RAW_SIZE + SLI_NLA_HDRLEN + 2;
  FATAL_ON(message_len >= UINT16_MAX);
  na->nla_len = (uint16_t)message_len;
  memcpy(NLA_DATA(na), Desc, SLI_CPC_HDLC_HEADER_RAW_SIZE);
  if (payload_size) {
    memcpy((char *)NLA_DATA(na) + SLI_CPC_HDLC_HEADER_RAW_SIZE, payload,
           payload_size);
  }
  req->netlink_msghdr.nlmsg_len += NLMSG_ALIGN(na->nla_len);
  return cmd_buff;
}

ssize_t sli_send_usr_cmd(uint8_t *buff, uint16_t bufLen)
{
  if (buff == NULL) {
    return NETLINK_SDIO_ERROR;
  }

  struct sockaddr_nl nladdr;
  ssize_t retval;
  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;

  retval = sendto(sli_linux_driver_app_cb.nl_sd, (char *)buff, bufLen,
                  0, (struct sockaddr *)&nladdr, sizeof(nladdr));
  if (retval < 0) {
    TRACE_DRIVER("sli_send_usr_cmd Failed");
  }
  return retval;
}

static int sli_create_nl_socket(int32_t protocol, int32_t groups)
{
  int fd;
  struct sockaddr_nl local;

  fd = socket(AF_NETLINK, SOCK_RAW, protocol);
  FATAL_SYSCALL_ON(fd < 0);

  memset(&local, 0, sizeof(local));
  local.nl_family = AF_NETLINK;
  local.nl_groups = (uint32_t)groups;
  local.nl_pid = WLAN_PORT_ID;
  if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
    close(fd);
    FATAL("Failed to bind netlink socket");
  }

  return fd;
}

static uint16_t sli_get_family_id(int socket_fd)
{
  sli_nlPkt_t *family_req;
  sli_nlPkt_t *ans;
  uint16_t id = 0;
  struct nlattr *na;
  int32_t rep_len;
  ssize_t ret;
  uint8_t *req_buff = NULL;
  uint8_t *rsp_buff = NULL;
  uint8_t family_name[] = "CTRL_PKT_TXRX";

  req_buff = malloc(NLMSG_LENGTH(GENL_HDRLEN)
                    + NLMSG_ALIGN(strlen((char *)family_name) + 1 + SLI_NLA_HDRLEN));
  FATAL_ON(req_buff == NULL);
  family_req = (sli_nlPkt_t *)req_buff;

  /* Get family name */
  family_req->netlink_msghdr.nlmsg_type = GENL_ID_CTRL;
  family_req->netlink_msghdr.nlmsg_flags = NLM_F_REQUEST;
  family_req->netlink_msghdr.nlmsg_seq = 0;
  family_req->netlink_msghdr.nlmsg_pid = (uint32_t)getpid();
  family_req->netlink_msghdr.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  family_req->genl_netlink_msghdr.cmd = CTRL_CMD_GETFAMILY;
  family_req->genl_netlink_msghdr.version = 0x1;

  na = (struct nlattr *)GENLMSG_DATA(req_buff);
  na->nla_type = CTRL_ATTR_FAMILY_NAME;

  na->nla_len = (__u16)(strlen((char *)family_name) + 1 + SLI_NLA_HDRLEN);
  strcpy((char *)NLA_DATA(na), (char *)family_name);

  family_req->netlink_msghdr.nlmsg_len += NLMSG_ALIGN(na->nla_len);

  ret = sli_sendto_fd(socket_fd, req_buff, (size_t)family_req->netlink_msghdr.nlmsg_len);
  free(req_buff);
  FATAL_ON(ret < 0);

  rsp_buff = malloc(MAX_RCV_SIZE);
  FATAL_ON(rsp_buff == NULL);

  ans = (sli_nlPkt_t *)rsp_buff;
  rep_len = (int32_t)recv(socket_fd, ans, MAX_RCV_SIZE, 0);
  if (rep_len < 0) {
    free(rsp_buff);
    FATAL("sli_get_family_id ERROR NUMBER = %d", errno);
  }

  // Validate response message
  if (!NLMSG_OK((&ans->netlink_msghdr), (uint32_t)rep_len)) {
    free(rsp_buff);
    FATAL("Invalid Response message");
  }

  if (ans->netlink_msghdr.nlmsg_type == NLMSG_ERROR) {
    free(rsp_buff);
    FATAL("NLMSG Type Error");
  }

  na = (struct nlattr *)GENLMSG_DATA(ans);
  na = (struct nlattr *)((char *)na + NLA_ALIGN(na->nla_len));
  if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
    id = *(__u16 *)NLA_DATA(na);
  }

  free(rsp_buff);

  return id;
}

static ssize_t sli_sendto_fd(int socket_fd, const uint8_t *buf, size_t bufLen)
{
  struct sockaddr_nl nladdr;
  ssize_t r;
  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;

  while ((r = sendto(socket_fd, buf, bufLen, 0, (struct sockaddr *)&nladdr,
                     sizeof(nladdr))) < (ssize_t)bufLen) {
    FATAL_ON(r > UINT16_MAX);
    if (r > 0) {
      buf += r;
      bufLen = bufLen - (size_t)r;
    } else if (errno != EAGAIN) {
      return NETLINK_SDIO_ERROR;
    }
  }

  return 0;
}
