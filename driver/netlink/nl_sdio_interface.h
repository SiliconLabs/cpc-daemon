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

#ifndef NL_SDIO_INTERFACE_H
#define NL_SDIO_INTERFACE_H

#include <linux/types.h>
#include <pthread.h>
#include <stdlib.h>

#define SLI_NL_APP_MAX_PAYLOAD_SIZE  4100 + 20  // 4100 maximum data payload size ; 20 is for to avoid unwanted portion

// host descriptor structure
typedef struct sli_frame_desc_s {
  // Data frame body length. Bits 14:12=queue, 000 for data, Bits 11:0 are the length
  uint8_t   frame_len_queue_no[2];
  // Frame type
  uint8_t   frame_type;
  // Unused , set to 0x00
  uint8_t   reserved[9];
  // Management frame descriptor response status, 0x00=success, else error
  uint8_t   status;
  uint8_t   reserved1[3];
} sli_frame_desc_t;

typedef struct pkt_struct_s{
  struct pkt_struct_s *next; // next packet pointer
  uint8_t desc[16]; // host descriptor
  uint8_t *data; // payload
}pkt_struct_t;

typedef struct {
  pkt_struct_t *head;                  // queue head
  pkt_struct_t *tail;                  // queue tail
  volatile uint16_t pending_pkt_count;            // pending packets in the queue
}pkt_queue_t;

typedef struct sli_linux_driver_cb_s{
  int32_t                nl_sd;          // netlink socket descriptor
  int32_t                ioctl_sd;       // socket descriptor of ioctl
  uint16_t               family_id;      // family id
  uint8_t                sli_glbl_genl_nl_hdr[20];
  uint8_t                mac_addr[6];
  uint32_t               num_rcvd_packets;
  pthread_mutex_t        mutex1;
  pkt_queue_t          rcv_queue;
}sli_linux_driver_cb_t;

/* Function prototypes */
ssize_t sli_execute_cmd(const uint8_t *desc, const uint8_t *payload, size_t size);
ssize_t nl_sdio_interface_register_irq(void);
int sl_nl_sdio_init(void);

extern void * RecvThreadBody(void *);
extern sli_linux_driver_cb_t sli_linux_driver_app_cb;

#endif // NL_SDIO_INTERFACE_H
