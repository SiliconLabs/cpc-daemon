/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) - UART XMODEM driver
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

#include "server_core/core/crc.h"
#include "driver/driver_xmodem.h"
#include "driver/driver_uart.h"
#include "misc/logging.h"
#include "misc/xmodem.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

int xmodem_send(const char* image_file, const char *dev_name, unsigned  int bitrate, bool hardflow)
{
  int uart_fd;
  int image_file_fd;
  uint8_t* mmaped_image_file_data;
  size_t mmaped_image_file_len;
  ssize_t ret;
  uint8_t answer;
  unsigned int retransmit_count = 0;

  /* Open the uart and memory map the firmware update file */
  {
    struct stat stat;

    uart_fd = driver_uart_open(dev_name, bitrate, hardflow);

    image_file_fd = open(image_file, O_RDONLY | O_CLOEXEC);
    FATAL_SYSCALL_ON(image_file_fd < 0);

    fstat(image_file_fd, &stat);

    mmaped_image_file_len = (size_t) stat.st_size;

    mmaped_image_file_data = mmap(NULL, mmaped_image_file_len, PROT_READ, MAP_PRIVATE, image_file_fd, 0);
    FATAL_SYSCALL_ON(mmaped_image_file_data == NULL);
  }

  /* Wait for the "C" character meaning the secondary is ready for XMODEM-CRC transfer */
  {
    sleep(1);

    /* The bootloader sends a menu with options. We have to send '1' in order to start a gbl file transfer */
    {
      const uint8_t upload_gbl[2] = "1\n";

      ret = write(uart_fd, &upload_gbl, sizeof(upload_gbl));
      FATAL_SYSCALL_ON(ret != sizeof(upload_gbl));
    }

    TRACE_XMODEM("Waiting for receiver ping ...");

    do {
      ret = read(uart_fd, &answer, sizeof(answer));
      FATAL_SYSCALL_ON(ret != sizeof(answer));
    } while (answer != XMODEM_CMD_C);

    TRACE_XMODEM("Received \"C\" ping. Transfer begins : ");
  }

  /* Actual file transfer */
  {
    XmodemFrame_t frame;
    uint8_t* image_file_data = mmaped_image_file_data;
    size_t image_file_len = mmaped_image_file_len;

    frame.header = XMODEM_CMD_SOH;
    frame.seq = 1; //Sequence number starts at one initially, wraps around to 0 afterward

    while (image_file_len) {
      size_t z = 0;
      bool proceed_to_next_frame = false;
      char status;

      z = min(image_file_len, sizeof(frame.data));

      memcpy(frame.data, image_file_data, z);
      memset(frame.data + z, 0xff, sizeof(frame.data) - z); //Pad last frame with 0xFF

      frame.crc = __builtin_bswap16(sli_cpc_get_crc_sw(frame.data, sizeof(frame.data)));

      frame.seq_neg = (uint8_t)(0xff - frame.seq);

      ret = write(uart_fd, &frame, sizeof(frame));
      FATAL_SYSCALL_ON(ret != sizeof(frame));

      ret = read(uart_fd, &answer, sizeof(answer));
      FATAL_SYSCALL_ON(ret != sizeof(answer));

      switch (answer) {
        case XMODEM_CMD_NAK:
          status = 'N';
          retransmit_count++;
          break;

        case XMODEM_CMD_ACK:
          status = '.';
          proceed_to_next_frame = true;
          break;

        default:
          FATAL("Error in file upload");
          break;
      }

      trace_no_timestamp("%c", status);

      if (proceed_to_next_frame) {
        frame.seq++;
        image_file_len -= z;
        image_file_data += z;
      }
    }
  }

  /* Complete the transfer by sending EOF symbol */
  {
    const uint8_t eof = XMODEM_CMD_EOT;

    ret = write(uart_fd, &eof, sizeof(eof));
    FATAL_SYSCALL_ON(ret != sizeof(eof));
  }

  TRACE_XMODEM("Transfer of file \"%s\" completed with %u retransmits.", image_file, retransmit_count);

  /* Give some room for the bootloader to send us the menu */
  sleep(1);

  /* Send '2' in order to run the new image */
  {
    const uint8_t run_gbl[2] = "2\n";

    ret = write(uart_fd, &run_gbl, sizeof(run_gbl));
    FATAL_SYSCALL_ON(ret != sizeof(run_gbl));
  }

  /* Cleanup */
  {
    ret = munmap(mmaped_image_file_data, mmaped_image_file_len);
    FATAL_SYSCALL_ON(ret != 0);

    ret = close(image_file_fd);
    FATAL_SYSCALL_ON(ret != 0);

    ret = close(uart_fd);
    FATAL_SYSCALL_ON(ret != 0);
  }

  PRINT_INFO("Firmware upgrade successfull. Exiting, restart CPCd without -f option.");

  exit(EXIT_SUCCESS);

  return 0;
}