/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol (CPC) - UART XMODEM driver
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

#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "cpcd/logging.h"
#include "cpcd/sleep.h"
#include "cpcd/utils.h"
#include "cpcd/xmodem.h"
#include "cpcd/endianness.h"

#include "server_core/core/crc.h"
#include "driver/driver_xmodem.h"
#include "driver/driver_uart.h"

#define BTL_MENU_PROMPT "BL >"
#define BTL_UPLOAD_CONFIRMATION "Serial upload complete"

#define MAX_RETRANSMIT_ATTEMPTS (5)

// Data from the bootloader comes in chunks
static bool wait_for_bootloader_string(int fd, const char *string)
{
  char btl_buffer[128] = { 0 };
  char *btl_chunk = btl_buffer;
  const uint8_t carriage_return = '\r';
  ssize_t ret;
  unsigned int retries = 10;

  // Receive data until the string is found
  do {
    sleep_s(1);

    int remaining = (int)sizeof(btl_buffer) - (int)(btl_chunk - btl_buffer);
    if (remaining <= 0) {
      return false;
    }

    ret = write(fd, (const void *)&carriage_return, sizeof(carriage_return));
    FATAL_SYSCALL_ON(ret != sizeof(carriage_return));

    ret = read(fd, btl_chunk, (size_t)remaining);
    FATAL_SYSCALL_ON(ret == -1 && errno != EAGAIN);

    btl_chunk += ret;

    retries--;
    if (retries == 0) {
      return false;
    }
  } while (NULL == strstr(btl_buffer, string));

  return true;
}

sl_status_t xmodem_uart_firmware_upgrade(const char* image_file, const char *dev_name, unsigned  int bitrate, bool hardflow)
{
  int uart_fd;
  int image_file_fd;
  uint8_t* mmapped_image_file_data;
  size_t mmapped_image_file_len;
  ssize_t sret;
  int ret;
  uint8_t answer;
  unsigned int retransmit_count = 0;

  // Open the uart and memory map the firmware update file
  {
    struct stat stat;

    uart_fd = driver_uart_open(dev_name, bitrate, hardflow);

    // make sure the file ends with .gbl
    if (is_valid_extension(image_file, "gbl") == false) {
      FATAL("The firmware upgrade file '%s' is not a .gbl file", image_file);
    }

    image_file_fd = open(image_file, O_RDONLY | O_CLOEXEC);
    FATAL_SYSCALL_ON(image_file_fd < 0);

    ret = fstat(image_file_fd, &stat);
    FATAL_SYSCALL_ON(ret < 0);

    mmapped_image_file_len = (size_t) stat.st_size;

    mmapped_image_file_data = mmap(NULL, mmapped_image_file_len, PROT_READ, MAP_PRIVATE, image_file_fd, 0);
    FATAL_SYSCALL_ON(mmapped_image_file_data == NULL);
  }

  // Wait for the "C" character meaning the secondary is ready for XMODEM-CRC transfer
  {
    // wait_for_bootloader_string implements a timeout, so fd must be non-blocking
    ret = fcntl(uart_fd, F_SETFL, O_NONBLOCK);
    FATAL_SYSCALL_ON(ret < 0);

    TRACE_XMODEM("Connecting to bootloader...");
    if (!wait_for_bootloader_string(uart_fd, BTL_MENU_PROMPT)) {
      TRACE_XMODEM("Failed to connect to bootloader.");
      return SL_STATUS_FAIL;
    }

    // The bootloader sends a menu with options. We have to send '1' in order to start a gbl file transfer
    const uint8_t upload_gbl = '1';
    TRACE_XMODEM("Received bootloader menu, send \"1\" to start gbl file transfer.");

    sret = write(uart_fd, (const void *)&upload_gbl, sizeof(upload_gbl));
    FATAL_SYSCALL_ON(sret != sizeof(upload_gbl));

    TRACE_XMODEM("Waiting for receiver ping ...");

    // Connection to the bootloader successful. Set the fd back to blocking so
    // it can wait for data from the remote.
    int flags = fcntl(uart_fd, F_GETFL);
    FATAL_SYSCALL_ON(flags < 0);
    flags &= ~O_NONBLOCK;
    ret = fcntl(uart_fd, F_SETFL, flags);
    FATAL_SYSCALL_ON(ret < 0);
    do {
      sret = read(uart_fd, &answer, sizeof(answer));
      FATAL_SYSCALL_ON(sret != sizeof(answer));
    } while (answer != XMODEM_CMD_C);

    TRACE_XMODEM("Received \"C\" ping. Transfer begins : ");
  }

  // Actual file transfer
  {
    XmodemFrame_t frame;
    uint8_t* image_file_data = mmapped_image_file_data;
    size_t image_file_len = mmapped_image_file_len;

    frame.header = XMODEM_CMD_SOH;
    frame.seq = 1; // Sequence number starts at one initially, wraps around to 0 afterward

    while (image_file_len) {
      size_t z = 0;
      bool proceed_to_next_frame = false;
      char status;

      z = min(image_file_len, sizeof(frame.data));

      memcpy(frame.data, image_file_data, z);
      memset(frame.data + z, 0xff, sizeof(frame.data) - z); // Pad last frame with 0xFF

      u16_to_be(sli_cpc_get_crc_sw(frame.data, sizeof(frame.data)), (uint8_t *)&frame.crc);

      frame.seq_neg = (uint8_t)(0xff - frame.seq);

      sret = write(uart_fd, &frame, sizeof(frame));
      FATAL_SYSCALL_ON(sret != sizeof(frame));

      sret = read(uart_fd, &answer, sizeof(answer));
      FATAL_SYSCALL_ON(sret != sizeof(answer));

      switch (answer) {
        case XMODEM_CMD_NAK:
          TRACE_XMODEM("Received XMODEM_CMD_NAK for frame number %d, retrying.", frame.seq);
          status = 'N';
          retransmit_count++;
          break;

        case XMODEM_CMD_ACK:
          TRACE_XMODEM("Sent frame number %d successfully.", frame.seq);
          status = '.';
          proceed_to_next_frame = true;
          retransmit_count = 0;
          break;

        default:
          FATAL("Error in file upload, received 0x%X when sending frame number %d.", answer, frame.seq);
          break;
      }

      trace_no_timestamp("%c", status);

      if (proceed_to_next_frame) {
        frame.seq++;
        image_file_len -= z;
        image_file_data += z;
      }

      if (retransmit_count > MAX_RETRANSMIT_ATTEMPTS) {
        TRACE_XMODEM("Max retries reached, exiting");
        return SL_STATUS_FAIL;
      }
    }
    TRACE_XMODEM("Finished sending image file. Sent a total of %zd Bytes.", (size_t)(image_file_data - mmapped_image_file_data));
    TRACE_XMODEM("Transfer of file \"%s\" completed with %u retransmits.", image_file, retransmit_count);
  }

  trace_no_timestamp("\n");

  // Complete the transfer by sending EOF symbol
  const uint8_t eof = XMODEM_CMD_EOT;
  TRACE_XMODEM("Sending EOT symbol to complete image file transfer.");
  sret = write(uart_fd, &eof, sizeof(eof));
  FATAL_SYSCALL_ON(sret != sizeof(eof));

  if (!wait_for_bootloader_string(uart_fd, BTL_UPLOAD_CONFIRMATION)) {
    TRACE_XMODEM("Failed to receive upload confirmation from bootloader.");
    return SL_STATUS_FAIL;
  }
  TRACE_XMODEM("Received upload confirmation from bootloader. Device restarting, waiting for bootloader menu...");

  if (!wait_for_bootloader_string(uart_fd, BTL_MENU_PROMPT)) {
    TRACE_XMODEM("Failed to restart device after upgrade.");
    return SL_STATUS_FAIL;
  }
  TRACE_XMODEM("Device restarted successfully.");

  // Send '2' in order to run the new image
  const uint8_t run_gbl = '2';
  TRACE_XMODEM("Received bootloader menu, send \"2\" to run the new image file.");
  sret = write(uart_fd, (const void *)&run_gbl, sizeof(run_gbl));
  FATAL_SYSCALL_ON(sret != sizeof(run_gbl));

  // Cleanup
  TRACE_XMODEM("Cleaning up...");
  ret = munmap(mmapped_image_file_data, mmapped_image_file_len);
  FATAL_SYSCALL_ON(ret != 0);

  ret = close(image_file_fd);
  FATAL_SYSCALL_ON(ret != 0);

  ret = close(uart_fd);
  FATAL_SYSCALL_ON(ret != 0);

  return SL_STATUS_OK;
}
