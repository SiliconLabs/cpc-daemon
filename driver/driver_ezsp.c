/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - EZSP-SPI driver
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
#define _GNU_SOURCE

#include <pthread.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>

#include "cpcd/logging.h"
#include "cpcd/sleep.h"
#include "cpcd/utils.h"
#include "cpcd/xmodem.h"

#include "server_core/core/crc.h"
#include "driver/driver_spi.h"
#include "driver/driver_ezsp.h"

#define START_BTL_FRAME   0xFD
#define END_BTL_FRAME     0xA7
#define SPI_STATUS        0x0B
#define SPI_VERSION       0x0A

#define BOOTLOADER_TIMEOUT      (20)
#define MAX_RETRANSMIT_ATTEMPTS (5)

#define TIMEOUT     0x16
#define FILEDONE    0x17
#define FILEABORT   0x18
#define BLOCKOK     0x19
#define QUERY       0x51
#define QUERYFOUND  0x1A

static cpc_spi_dev_t spi_dev;

static struct spi_ioc_transfer spi_transfer;

static uint8_t rx_spi_buffer[SPI_BUFFER_SIZE];
static uint8_t tx_spi_buffer[SPI_BUFFER_SIZE];

static int read_until_end_of_frame(void);
static bool wait_irq_line(void);
static int send_query(void);
static bool send_end_of_file(void);
static bool ezsp_send_bootloader_raw_bytes(const uint8_t *message, uint8_t length);

static void driver_ezsp_spi_open(const char   *device,
                                 uint32_t speed,
                                 const char *irq_gpio_chip,
                                 unsigned int irq_gpio_pin);

sl_status_t send_firmware(const char   * image_file,
                          const char   *device,
                          unsigned int speed,
                          const char *irq_gpio_chip,
                          unsigned int irq_gpio_pin)
{
  struct stat stat;
  int ret = 0;
  int image_file_fd;
  uint8_t* mmaped_image_file_data;
  size_t mmaped_image_file_len;
  unsigned int retransmit_count = 0;
  bool error = false;
  size_t z = 0;
  bool proceed_to_next_frame = false;
  char status;
  int retries = 0;
  XmodemFrame_t frame;
  uint8_t* image_file_data;
  size_t image_file_len;
  enum {
    GET_INFO,
    SEND_FRAMES,
    SEND_EOT,
    CONFIRM_EOT,
    CLEAN_UP
  } state = GET_INFO;

  // open connection to secondary
  driver_ezsp_spi_open(device,
                       speed,
                       irq_gpio_chip,
                       irq_gpio_pin);

  // load file from fs and prepare first frame
  image_file_fd = open(image_file, O_RDONLY | O_CLOEXEC);
  FATAL_SYSCALL_ON(image_file_fd < 0);

  fstat(image_file_fd, &stat);

  mmaped_image_file_len = (size_t) stat.st_size;

  mmaped_image_file_data = mmap(NULL, mmaped_image_file_len, PROT_READ, MAP_PRIVATE, image_file_fd, 0);
  FATAL_SYSCALL_ON(mmaped_image_file_data == NULL);

  image_file_data = mmaped_image_file_data;
  image_file_len = mmaped_image_file_len;

  frame.header = XMODEM_CMD_SOH;
  frame.seq = 1;   //Sequence number starts at one initially, wraps around to 0 afterward

  TRACE_EZSP_SPI("===== State: GET_INFO =====");
  TRACE_EZSP_SPI("Sending query to bootloader.");

  while (1) {
    if (retries > MAX_RETRANSMIT_ATTEMPTS) {
      TRACE_EZSP_SPI("Max retries, exiting");
      error = true;
      state = CLEAN_UP;
      TRACE_EZSP_SPI("===== State: CLEAN_UP =====");
    }
    switch (state) {
      case GET_INFO:
        retries++;
        // bootloader will return QUERYFOUND when ready
        ret = send_query();
        if (ret == QUERYFOUND) {
          // bootloader returns device info
          TRACE_EZSP_SPI("Received QUERYFOUND, bootloader ready.");
          send_query();
          retries = 0;
          state = SEND_FRAMES;
          TRACE_EZSP_SPI("===== State: SEND_FRAMES =====");
          TRACE_EZSP_SPI("Starting image file transmission.");
        } else {
          TRACE_EZSP_SPI("Failed to receive QUERYFOUND, received 0x%X. Retrying.", ret);
        }
        break;
      case SEND_FRAMES:
        z = min(image_file_len, sizeof(frame.data));

        memcpy(frame.data, image_file_data, z);
        // 0x1A padding
        memset(frame.data + z, 0x1A, sizeof(frame.data) - z);

        frame.crc = __builtin_bswap16(sli_cpc_get_crc_sw(frame.data, sizeof(frame.data)));

        frame.seq_neg = (uint8_t)(0xff - frame.seq);

        proceed_to_next_frame = ezsp_send_bootloader_raw_bytes((const uint8_t *)&frame, sizeof(frame));

        if (proceed_to_next_frame) {
          TRACE_EZSP_SPI("Sent frame number %d successfully.", frame.seq);
          frame.seq++;
          image_file_len -= z;
          image_file_data += z;
          status = '.';
          retries = 0;
        } else {
          TRACE_EZSP_SPI("Failed to send frame number %d, retrying.", frame.seq);
          status = 'N';
          retransmit_count++;
          retries++;
        }
        trace_no_timestamp("%c", status);

        if (image_file_len == 0) {
          TRACE_EZSP_SPI("Finished sending image file. Sent a total of %d Bytes.", (size_t)(image_file_data - mmaped_image_file_data));
          trace_no_timestamp("\n");
          retries = 0;
          state = SEND_EOT;
          TRACE_EZSP_SPI("===== State: SEND_EOT =====");
        }
        break;
      case SEND_EOT:
        if (send_end_of_file()) {
          TRACE_EZSP_SPI("Transfer of file \"%s\" completed with %u retransmits.", image_file, retransmit_count);
          retries = 0;
          state = CONFIRM_EOT;
          TRACE_EZSP_SPI("===== State: CONFIRM_EOT =====");
        } else {
          retries++;
        }
        break;
      case CONFIRM_EOT:
        ret = send_query();
        // bootloader should respond with an ACK and the last frame number + 1
        if ((ret == XMODEM_CMD_ACK) && (rx_spi_buffer[3] == frame.seq)) {
          TRACE_EZSP_SPI("Received EOT confirmation, cleaning up...");
          retries = 0;
          state = CLEAN_UP;
          TRACE_EZSP_SPI("===== State: CLEAN_UP =====");
        } else {
          TRACE_EZSP_SPI("Failed to receive EOT confirmation for final frame number %d."
                         "Received 0x%X for frame number %d instead. Retrying.", frame.seq, ret, rx_spi_buffer[3]);
          retries++;
          // the confirmation can take ~3 seconds
          sleep_s(1);
        }
        break;
      case CLEAN_UP:
      default:
        ret = munmap(mmaped_image_file_data, mmaped_image_file_len);
        FATAL_SYSCALL_ON(ret != 0);

        ret = close(image_file_fd);
        FATAL_SYSCALL_ON(ret != 0);

        ret = close(spi_dev.spi_dev_descriptor);
        FATAL_SYSCALL_ON(ret != 0);

        if (error) {
          return SL_STATUS_FAIL;
        } else {
          return SL_STATUS_OK;
        }
        break;
    }
    sleep_ms(1);
  }
}

static void driver_ezsp_spi_open(const char   *device,
                                 uint32_t speed,
                                 const char *irq_gpio_chip,
                                 unsigned int irq_gpio_pin)
{
  int ret = 0;
  int fd;
  TRACE_EZSP_SPI("Opening EZSP interface...");

  memset(&spi_transfer, 0, sizeof(struct spi_ioc_transfer));

  // SPIDEV0: MOSI (GPIO10); MISO (GPIO9); SCLK (GPIO11); RX_IRQ (GPIO23); CS (GPIO24)
  fd = open(device, O_RDWR | O_CLOEXEC);
  FATAL_SYSCALL_ON(fd < 0);

  uint8_t mode = SPI_MODE_0;
  ret = ioctl(fd, SPI_IOC_WR_MODE, &mode);
  FATAL_SYSCALL_ON(ret < 0);

  uint8_t bit_per_word = 8;
  ret = ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bit_per_word);
  FATAL_SYSCALL_ON(ret < 0);

  spi_transfer.bits_per_word = bit_per_word;

  ret = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
  FATAL_SYSCALL_ON(ret < 0);

  spi_transfer.speed_hz = speed;

  spi_transfer.rx_buf = (uintptr_t)rx_spi_buffer;
  spi_transfer.tx_buf = (uintptr_t)tx_spi_buffer;

  spi_dev.spi_dev_descriptor = fd;

  // Setup IRQ gpio
  FATAL_ON(gpio_init(&spi_dev.irq_gpio, irq_gpio_chip, irq_gpio_pin, IN, FALLING) < 0);
  TRACE_EZSP_SPI("EZSP interface opened successfully.");
}

static int read_until_end_of_frame(void)
{
  uint8_t temp_array[SPI_BUFFER_SIZE];
  uint16_t cpt = 0;
  bool valid_data = false;
  int ret = 0;
  int timeout = BOOTLOADER_TIMEOUT;

  memset(tx_spi_buffer, 0xFF, SPI_BUFFER_SIZE);
  memset(rx_spi_buffer, 0, SPI_BUFFER_SIZE);

  spi_transfer.len = 1u;

  spi_transfer.cs_change = 1;

  do {
    if (cpt >= SPI_BUFFER_SIZE) {
      TRACE_EZSP_SPI("Tried to write outside the rx_buffer while waiting for EOF.");
      return -1;
    }
    ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_transfer);
    FATAL_ON(ret != 1);
    if (rx_spi_buffer[0] != 0xFF) {
      valid_data = true;
    }
    if (valid_data) {
      temp_array[cpt++] = rx_spi_buffer[0];
    } else {
      timeout--;
    }
  } while ((rx_spi_buffer[0] != END_BTL_FRAME) && (timeout > 0));

  spi_transfer.cs_change = 0;
  ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_transfer);

  if (timeout == 0) {
    TRACE_EZSP_SPI("Timed out while waiting for EOF.");
    return -1;
  }

  memcpy(rx_spi_buffer, temp_array, cpt);

  return cpt;
}

static bool wait_irq_line(void)
{
  int timeout = BOOTLOADER_TIMEOUT;

  while ((gpio_read(&spi_dev.irq_gpio) != 0)
         && timeout-- > 0) {
    sleep_ms(10);
  }

  if (timeout <= 0) {
    return false;
  }

  sleep_ms(1);
  return true;
}

static int send_query(void)
{
  int ret = 0;

  memset(tx_spi_buffer, 0xFF, SPI_BUFFER_SIZE);
  memset(rx_spi_buffer, 0, SPI_BUFFER_SIZE);

  // [FD 01 51 A7]
  spi_transfer.len = 4u;

  tx_spi_buffer[0] = START_BTL_FRAME;
  tx_spi_buffer[1] = 0x01; // length
  tx_spi_buffer[2] = QUERY;
  tx_spi_buffer[3] = END_BTL_FRAME;

  spi_transfer.cs_change = 1;
  ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_transfer);
  FATAL_ON(ret != 4);

  if (!wait_irq_line()) {
    TRACE_EZSP_SPI("Timed out while waiting for the IRQ line to go high while sending query.");
    return -1;
  }

  ret = read_until_end_of_frame();
  if (ret < 0) {
    TRACE_EZSP_SPI("Timed out while waiting for the end of frame while sending query.");
    return -1;
  }

  return rx_spi_buffer[2];
}

static bool send_end_of_file(void)
{
  int ret = 0;

  memset(tx_spi_buffer, 0xFF, SPI_BUFFER_SIZE);
  memset(rx_spi_buffer, 0, SPI_BUFFER_SIZE);

  spi_transfer.len = 4u;

  // [FD 01 04 A7]
  tx_spi_buffer[0] = START_BTL_FRAME;
  tx_spi_buffer[1] = 0x01; // length
  tx_spi_buffer[2] = XMODEM_CMD_EOT;
  tx_spi_buffer[3] = END_BTL_FRAME;

  spi_transfer.cs_change = 1;
  ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_transfer);
  FATAL_ON(ret != 4);

  if (!wait_irq_line()) {
    TRACE_EZSP_SPI("Timed out while waiting for the IRQ line to go high while waiting for EOF.");
    return false;
  }

  ret = read_until_end_of_frame();
  if (ret < 0) {
    TRACE_EZSP_SPI("Timed out while waiting for the end of frame while sending EOF.");
    return -1;
  }

  if (rx_spi_buffer[2] == FILEDONE) {
    TRACE_EZSP_SPI("Received FILEDONE.");
    return true;
  }

  TRACE_EZSP_SPI("Failed to receive FILEDONE, received 0x%X instead.", rx_spi_buffer[2]);
  return false;
}

static bool ezsp_send_bootloader_raw_bytes(const uint8_t *message, uint8_t length)
{
  int ret = 0;
  int timeout = 5;
  uint8_t seq_no = ((XmodemFrame_t *)message)->seq;

  memset(tx_spi_buffer, 0xFF, SPI_BUFFER_SIZE);
  memset(rx_spi_buffer, 0, SPI_BUFFER_SIZE);

  // Build ezsp frame
  tx_spi_buffer[0] = START_BTL_FRAME;
  tx_spi_buffer[1] = length;
  memcpy((void *)&tx_spi_buffer[2], message, length);
  tx_spi_buffer[length + 2] = END_BTL_FRAME;

  spi_transfer.len = length + 3u;

  spi_transfer.cs_change = 1;
  ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_transfer);
  FATAL_ON(ret != (int)(length) + 3);

  if (!wait_irq_line()) {
    TRACE_EZSP_SPI("Timed out while waiting for the IRQ line to go high after sending FW frame number %d to the bootloader.", seq_no);
    return false;
  }

  // the bootloader should respond to the transmission
  // with BLOCKOK
  ret = read_until_end_of_frame();
  if (ret < 0) {
    TRACE_EZSP_SPI("Timed out while waiting for EOF after sending FW frame number %d to the bootloader.", seq_no);
    return false;
  }

  if (rx_spi_buffer[2] != BLOCKOK) {
    TRACE_EZSP_SPI("Received 0x%X instead of BLOCKOK for frame number 0x%X.", rx_spi_buffer[2], seq_no);
    return false;
  }

  // a subsequent send_query should return an XMODEM ACK with
  // the seq number
  while ((send_query() != XMODEM_CMD_ACK) && (timeout-- > 0)) {
    sleep_ms(1);
  }
  if (timeout <= 0) {
    TRACE_EZSP_SPI("Failed to get a XMODEM_ACK after writing frame numer %d", seq_no);
    return false;
  }

  if (rx_spi_buffer[3] != seq_no) {
    TRACE_EZSP_SPI("Received XMODEM_CMD_ACK for frame number %d instead of %d.", rx_spi_buffer[3], seq_no);
    return false;
  }

  return true;
}
