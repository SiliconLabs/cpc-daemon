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

#include "config.h"

#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>

#include "cpcd/config.h"
#include "cpcd/logging.h"
#include "cpcd/sleep.h"
#include "cpcd/utils.h"
#include "cpcd/xmodem.h"
#include "cpcd/endianness.h"

#include "server_core/core/crc.h"
#include "server_core/core/hdlc.h"
#include "driver/driver_spi.h"
#include "driver/driver_ezsp.h"

#define BOOTLOADER_TIMEOUT      (20)
#define MAX_RETRANSMIT_ATTEMPTS (5)
#define IRQ_FALLING_EDGE_TIMEOUT_MS 1000

#define START_BTL_FRAME   0xFD
#define END_BTL_FRAME     0xA7
#define SPI_STATUS        0x0B
#define SPI_VERSION       0x0A

enum ezsp_spi_frame_btl {
  EZSP_SPI_FRAME_BTL_QUERY               = 0x51,
  EZSP_SPI_FRAME_BTL_QUERYRESP           = 0x52,
  EZSP_SPI_FRAME_BTL_QUERYFOUND          = 0x1A,
  EZSP_SPI_FRAME_BTL_NO_QUERY            = 0x4D,
  EZSP_SPI_FRAME_BTL_TIMEOUT             = 0x16,
  EZSP_SPI_FRAME_BTL_FILEDONE            = 0x17,
  EZSP_SPI_FRAME_BTL_FILEABORT           = 0x18,
  EZSP_SPI_FRAME_BTL_BLOCKOK             = 0x19,
  EZSP_SPI_FRAME_BTL_START_TIMEOUT       = 0x1B,
  EZSP_SPI_FRAME_BTL_BLOCKERR_TIMEOUT    = 0x1C,
  EZSP_SPI_FRAME_BTL_BLOCKERR_SOH        = 0x21,
  EZSP_SPI_FRAME_BTL_BLOCKERR_CHK        = 0x22,
  EZSP_SPI_FRAME_BTL_BLOCKERR_CRCH       = 0x23,
  EZSP_SPI_FRAME_BTL_BLOCKERR_CRCL       = 0x24,
  EZSP_SPI_FRAME_BTL_BLOCKERR_SEQUENCE   = 0x25,
  EZSP_SPI_FRAME_BTL_BLOCKERR_PARTIAL    = 0x26,
  EZSP_SPI_FRAME_BTL_BLOCKERR_DUP        = 0x27
};

static const char* ezsp_spi_frame_to_str(enum ezsp_spi_frame_btl ezsp_btl)
{
  switch (ezsp_btl) {
    case EZSP_SPI_FRAME_BTL_QUERY:
      return "QUERY";
    case EZSP_SPI_FRAME_BTL_QUERYRESP:
      return "QUERYRESP";
    case EZSP_SPI_FRAME_BTL_QUERYFOUND:
      return "QUERYFOUND";
    case EZSP_SPI_FRAME_BTL_NO_QUERY:
      return "NO_QUERY";
    case EZSP_SPI_FRAME_BTL_TIMEOUT:
      return "TIMEOUT";
    case EZSP_SPI_FRAME_BTL_FILEDONE:
      return "FILEDONE";
    case EZSP_SPI_FRAME_BTL_FILEABORT:
      return "FILEABORT";
    case EZSP_SPI_FRAME_BTL_BLOCKOK:
      return "BLOCKOK";
    case EZSP_SPI_FRAME_BTL_START_TIMEOUT:
      return "START_TIMEOUT";
    case EZSP_SPI_FRAME_BTL_BLOCKERR_TIMEOUT:
      return "BLOCKERR_TIMEOUT";
    case EZSP_SPI_FRAME_BTL_BLOCKERR_SOH:
      return "BLOCKERR_SOH";
    case EZSP_SPI_FRAME_BTL_BLOCKERR_CHK:
      return "BLOCKERR_CHK";
    case EZSP_SPI_FRAME_BTL_BLOCKERR_CRCH:
      return "BLOCKERR_CRCH";
    case EZSP_SPI_FRAME_BTL_BLOCKERR_CRCL:
      return "BLOCKERR_CRCL";
    case EZSP_SPI_FRAME_BTL_BLOCKERR_SEQUENCE:
      return "BLOCKERR_SEQUENCE";
    case EZSP_SPI_FRAME_BTL_BLOCKERR_PARTIAL:
      return "BLOCKERR_PARTIAL";
    case EZSP_SPI_FRAME_BTL_BLOCKERR_DUP:
      return "BLOCKERR_DUP";
    default:
      return "?";
  }
}

// Since it is unknown which of the USART or EUSART the bootloader is using, pick
// a reasonable common lower denominator between the USART and EUSART max bitrate
#define FWU_MAX_BITRATE 1000000

struct spi_interface {
  int spi_dev_fd;
  gpio_t irq_gpio;
  struct spi_ioc_transfer spi_transfer;
  int epoll_fd;
};

struct fwu_image {
  int fd;
  uint8_t *data;
  size_t size;
};

struct __attribute__((packed)) spi_xmodem_buffer {
  uint8_t start;
  uint8_t size;
  XmodemFrame_t frame;
  uint8_t end;
};

/***************************************************************************//**
 * Initialize the SPI interface including the IRQ pin
 ******************************************************************************/
static void open_spi_interface(const char   *device,
                               uint32_t     bitrate,
                               const char   *irq_gpio_chip,
                               unsigned int irq_gpio_pin,
                               struct spi_interface *spi)
{
  int ret = 0;

  // Init the SPI bus
  {
    memset(&spi->spi_transfer, 0, sizeof(struct spi_ioc_transfer));

    spi->spi_dev_fd = open(device, O_RDWR | O_CLOEXEC);
    FATAL_SYSCALL_ON(spi->spi_dev_fd < 0);

    uint8_t mode = SPI_MODE_0;
    ret = ioctl(spi->spi_dev_fd, SPI_IOC_WR_MODE, &mode);
    FATAL_SYSCALL_ON(ret < 0);

    uint8_t bit_per_word = 8;
    ret = ioctl(spi->spi_dev_fd, SPI_IOC_WR_BITS_PER_WORD, &bit_per_word);
    FATAL_SYSCALL_ON(ret < 0);

    spi->spi_transfer.bits_per_word = bit_per_word;

    // Since it can't be known whether the bootloader uses the USART or EUSART,
    // clip the bitrate to the maximum supported by the USART, which is the lowest
    uint32_t chosen_bitrate = (bitrate > FWU_MAX_BITRATE) ? FWU_MAX_BITRATE : bitrate;

    ret = ioctl(spi->spi_dev_fd, SPI_IOC_WR_MAX_SPEED_HZ, &chosen_bitrate);
    FATAL_SYSCALL_ON(ret < 0);

    spi->spi_transfer.speed_hz = chosen_bitrate;
  }

  // Setup IRQ GPIO
  {
    struct epoll_event event = { 0 };

    spi->irq_gpio = gpio_init(irq_gpio_chip, irq_gpio_pin, GPIO_DIRECTION_IN, GPIO_EDGE_FALLING);

    spi->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    FATAL_SYSCALL_ON(spi->epoll_fd < 0);

    event.events = GPIO_EPOLL_EVENT;
    event.data.fd = gpio_get_epoll_fd(spi->irq_gpio);
    ret = epoll_ctl(spi->epoll_fd, EPOLL_CTL_ADD, gpio_get_epoll_fd(spi->irq_gpio), &event);
    FATAL_SYSCALL_ON(ret < 0);
  }
}

/***************************************************************************//**
 * Closes the SPI interface opened by open_spi_interface
 ******************************************************************************/
static void close_spi_interface(const struct spi_interface *spi)
{
  int ret;

  ret = close(spi->epoll_fd);
  FATAL_SYSCALL_ON(ret != 0);

  ret = close(spi->spi_dev_fd);
  FATAL_SYSCALL_ON(ret != 0);

  gpio_deinit(spi->irq_gpio);
}

/***************************************************************************//**
 * Opens the firmware upgrade image file
 *
 * @note : A check is performed on the file extension to make sure a proper .gbl
 *         file is opened
 *
 * @param image : the image struct opened by open_fwu_image
 *
 * @param [in] image_file : The image file name string to send
 *        [out] image : The opened image
 ******************************************************************************/
static void open_fwu_image(const char* const image_file, struct fwu_image *image)
{
  struct stat stat;

  if (is_valid_extension(image_file, "gbl") == false) {
    FATAL("The firmware upgrade file '%s' is not a .gbl file", image_file);
  }

  image->fd = open(image_file, O_RDONLY | O_CLOEXEC);
  FATAL_SYSCALL_ON(image->fd < 0);

  fstat(image->fd, &stat);

  image->size = (size_t) stat.st_size;

  image->data = mmap(NULL, image->size, PROT_READ, MAP_PRIVATE, image->fd, 0);
  FATAL_SYSCALL_ON(image->data == NULL);
}

/***************************************************************************//**
 * Closes the firmware upgrade image opened by open_fwu_image
 *
 * @param image : the image struct opened by open_fwu_image
 ******************************************************************************/
static void close_fwu_image(const struct fwu_image *image)
{
  int ret;

  ret = munmap(image->data, image->size);
  FATAL_SYSCALL_ON(ret != 0);

  ret = close(image->fd);
  FATAL_SYSCALL_ON(ret != 0);
}

/***************************************************************************//**
 * Wait for an IRQ falling-edge event or until the timeout or
 * IRQ_FALLING_EDGE_TIMEOUT_MS is reached
 *
 * @return SL_STATUS_OK : the IRQ falling-edge event occurred before the timeout
 *         SL_STATUS_TIMEOUT : timed out before the IRQ falling-edge event
 ******************************************************************************/
static sl_status_t wait_irq_falling_edge(const struct spi_interface *spi, int timeout_ms)
{
  struct epoll_event event;
  int event_count;
  const int MAX_EPOLL_EVENTS = 1;

  while (1) {
    event_count = epoll_wait(spi->epoll_fd,
                             &event,
                             MAX_EPOLL_EVENTS,
                             timeout_ms);

    if (event_count == -1 && errno == EINTR) {
      // This thread woke up because of a signal, to back to waiting
      continue;
    }

    // Check for call errors
    FATAL_SYSCALL_ON(event_count == -1);
    BUG_ON(event_count > 1);

    if (event_count == 1) {
      BUG_ON(event.data.fd != gpio_get_epoll_fd(spi->irq_gpio));

      if (gpio_read(spi->irq_gpio) == GPIO_VALUE_HIGH) {
        gpio_clear_irq(spi->irq_gpio);
        // There is a spurious glitch event problem possibility on RPIs when using gpiod
        // If such a glitch is detected, to back to waiting
        continue;
      }
    }

    // True falling-edge event or timeout occurred
    break;
  }

  if (event_count == 0) {
    return SL_STATUS_TIMEOUT;
  } else {
    return SL_STATUS_OK;
  }
}

/***************************************************************************//**
 * Simply de-assert CS pin, no data transfered
 ******************************************************************************/
static void de_assert_cs(struct spi_interface *spi)
{
  int ret;

  spi->spi_transfer.len = 0;
  spi->spi_transfer.cs_change = 0; // De-assert CS

  ret = ioctl(spi->spi_dev_fd, SPI_IOC_MESSAGE(1), &spi->spi_transfer);
  FATAL_ON(ret != (int) spi->spi_transfer.len);
}

/***************************************************************************//**
 * Sends the SPI STATUS command and expect either a bootloader reset reason or
 * the SPI STATUS command reply.
 ******************************************************************************/
static sl_status_t pull_reset_reason_or_spi_status(struct spi_interface *spi)
{
  const uint8_t btl_response_reset_reason[]  = { 0xFF, 0xFF, 0x00, 0x09, END_BTL_FRAME };
  const uint8_t btl_response_spi_status[]    = { 0xFF, 0xFF, 0xC1, END_BTL_FRAME, 0xFF };
  const uint8_t btl_response_spi_status2[]   = { 0xFF, 0xFF, 0xC0, END_BTL_FRAME, 0xFF };
  const uint8_t spi_status_tx_buffer[2] = { SPI_STATUS, END_BTL_FRAME };
  uint8_t rx_buffer[5];
  int ret;

  // Clear any stale IRQ falling-edge event
  gpio_clear_irq(spi->irq_gpio);

  spi->spi_transfer.len = 2u;
  spi->spi_transfer.cs_change = 1; // Keep CS asserted
  spi->spi_transfer.tx_buf = (unsigned long) spi_status_tx_buffer;
  spi->spi_transfer.rx_buf = (unsigned long) &rx_buffer[0];

  ret = ioctl(spi->spi_dev_fd, SPI_IOC_MESSAGE(1), &spi->spi_transfer);
  FATAL_ON(ret != (int) spi->spi_transfer.len);

  sl_status_t status = wait_irq_falling_edge(spi, IRQ_FALLING_EDGE_TIMEOUT_MS);

  if (status == SL_STATUS_TIMEOUT) {
    TRACE_EZSP_SPI("[pull reset reason] FAIL : IRQ falling-edge timeout");

    de_assert_cs(spi);

    // command failed because of timeout
    return SL_STATUS_TIMEOUT;
  }

  gpio_clear_irq(spi->irq_gpio);

  spi->spi_transfer.len = 3u;
  spi->spi_transfer.cs_change = 0; // De-assert CS
  spi->spi_transfer.tx_buf = (unsigned long) NULL;
  spi->spi_transfer.rx_buf = (unsigned long) &rx_buffer[2];

  ret = ioctl(spi->spi_dev_fd, SPI_IOC_MESSAGE(1), &spi->spi_transfer);
  FATAL_ON(ret != (int) spi->spi_transfer.len);

  if (0 == memcmp(rx_buffer, btl_response_reset_reason, sizeof(btl_response_reset_reason))
      || 0 == memcmp(rx_buffer, btl_response_spi_status, sizeof(btl_response_spi_status))
      || 0 == memcmp(rx_buffer, btl_response_spi_status2, sizeof(btl_response_spi_status2))) {
    return SL_STATUS_OK;
  } else {
    TRACE_EZSP_SPI("[pull reset reason] FAIL : Unrecognized response : {0x%x 0x%x 0x%x 0x%x 0x%x}", rx_buffer[0], rx_buffer[1], rx_buffer[2], rx_buffer[3], rx_buffer[4]);
    TRACE_EZSP_SPI("Expected : {0xFF, 0xFF, 0x00, 0x09, 0xA7} or {0xFF, 0xFF, 0xC1, 0xA7, 0xFF} or {0xFF, 0xFF, 0xC0, 0xA7, 0xFF}");
    return SL_STATUS_FAIL;
  }
}

static sl_status_t pull_reset_reason_or_spi_status_with_retries(struct spi_interface *spi)
{
  sl_status_t status;
  size_t retries =  MAX_RETRANSMIT_ATTEMPTS;

  while (retries--) {
    status = pull_reset_reason_or_spi_status(spi);

    if (status == SL_STATUS_OK) {
      return SL_STATUS_OK;
    }
  }

  return status;
}
/***************************************************************************//**
 * Sends an EZSP command
 *
 * @param command : The command byte
 *
 * @return SL_STATUS_TIMEOUT : Timeout on falling-edge of IRQ
 *         SL_STATUS_FAIL : The response format was bad
 *         SL_STATUS_OK : The command was successful and the response was written
 *                        to 'rx_buffer'
 ******************************************************************************/
static sl_status_t send_command(struct spi_interface *spi, uint8_t command, uint8_t * const rx_buffer)
{
  int ret;
  uint8_t query_tx_buffer[4] = { START_BTL_FRAME, 0x01, 0x00, END_BTL_FRAME };

  query_tx_buffer[2] = command;

  spi->spi_transfer.len = 4u;
  spi->spi_transfer.cs_change = 1; // Keep CS asserted
  spi->spi_transfer.tx_buf = (unsigned long) query_tx_buffer;
  spi->spi_transfer.rx_buf = (unsigned long) NULL;

  // Clear any stale IRQ falling-edge event
  gpio_clear_irq(spi->irq_gpio);

  // Send the 4 bytes command and keep CS low
  ret = ioctl(spi->spi_dev_fd, SPI_IOC_MESSAGE(1), &spi->spi_transfer);
  FATAL_ON(ret != (int) spi->spi_transfer.len);

  sl_status_t status = wait_irq_falling_edge(spi, IRQ_FALLING_EDGE_TIMEOUT_MS);

  if (status == SL_STATUS_TIMEOUT) {
    TRACE_EZSP_SPI("[send command] FAIL : IRQ falling-edge timeout");

    de_assert_cs(spi);

    // command failed because of timeout
    return SL_STATUS_TIMEOUT;
  }

  // Acknowledge the IRQ falling-edge event
  gpio_clear_irq(spi->irq_gpio);

  // Now that the bootloader pulled IRQ low, it means it is ready
  // Pull two bytes
  spi->spi_transfer.len = 2u;
  spi->spi_transfer.tx_buf = (unsigned long) NULL;
  spi->spi_transfer.rx_buf = (unsigned long) rx_buffer;

  ret = ioctl(spi->spi_dev_fd, SPI_IOC_MESSAGE(1), &spi->spi_transfer);
  FATAL_ON(ret != (int) spi->spi_transfer.len);

  if (rx_buffer[0] != START_BTL_FRAME) {
    // The start byte is wrong, bring back CS high and bail

    de_assert_cs(spi);

    TRACE_EZSP_SPI("[send command] FAIL : Wrong start of frame. Received 0x%x, expected 0x%x", rx_buffer[0], START_BTL_FRAME);

    return SL_STATUS_FAIL;
  }

  uint8_t payload_length = rx_buffer[1];

  // Pull one more byte than the payload_length for the end byte
  spi->spi_transfer.len = payload_length + 1u;
  spi->spi_transfer.cs_change = 0; // De-assert CS
  spi->spi_transfer.tx_buf = (unsigned long) NULL;
  spi->spi_transfer.rx_buf = (unsigned long) &rx_buffer[2];

  ret = ioctl(spi->spi_dev_fd, SPI_IOC_MESSAGE(1), &spi->spi_transfer);
  FATAL_ON(ret != (int) spi->spi_transfer.len);

  if (rx_buffer[spi->spi_transfer.len + 1] != END_BTL_FRAME) {
    TRACE_EZSP_SPI("[send command] FAIL : Wrong end of frame. Received 0x%x, expected 0x%x", rx_buffer[spi->spi_transfer.len + 2], END_BTL_FRAME);

    return SL_STATUS_FAIL;
  }

  // The returned data is in the rx_buffer buffer

  return SL_STATUS_OK;
}

static sl_status_t send_command_with_retries(struct spi_interface *spi, uint8_t command, uint8_t * const rx_buffer)
{
  sl_status_t status = SL_STATUS_OK;
  size_t retries =  MAX_RETRANSMIT_ATTEMPTS;

  while (retries--) {
    status = send_command(spi, command, rx_buffer);

    if (status == SL_STATUS_OK) {
      return SL_STATUS_OK;
    }
  }

  return status;
}

static sl_status_t send_frame(struct spi_interface *spi, struct spi_xmodem_buffer *spi_xmodem_buffer)
{
  int ret;
  sl_status_t status;
  uint8_t rx_buffer[128];

  // Clear any stale IRQ falling-edge event
  gpio_clear_irq(spi->irq_gpio);

  // Send the XMDODEM frame and keep CS asserted since is needs to remain asserted
  // for the whole duration of the transaction
  {
    spi->spi_transfer.len = sizeof(struct spi_xmodem_buffer);
    spi->spi_transfer.cs_change = 1; // Assert CS
    spi->spi_transfer.tx_buf = (unsigned long) spi_xmodem_buffer;
    spi->spi_transfer.rx_buf = (unsigned long) NULL;

    ret = ioctl(spi->spi_dev_fd, SPI_IOC_MESSAGE(1), &spi->spi_transfer);
    FATAL_ON(ret != (int) spi->spi_transfer.len);
  }

  // Wait for falling edge of IRQ
  {
    status = wait_irq_falling_edge(spi, IRQ_FALLING_EDGE_TIMEOUT_MS);

    if (status == SL_STATUS_TIMEOUT) {
      TRACE_EZSP_SPI("[send frame] FAIL : IRQ falling-edge timeout");
      de_assert_cs(spi);
      return SL_STATUS_TIMEOUT;
    }
    gpio_clear_irq(spi->irq_gpio);
  }

  // Pull the start and the length byte
  {
    spi->spi_transfer.len = 2u;
    spi->spi_transfer.tx_buf = (unsigned long) NULL;
    spi->spi_transfer.rx_buf = (unsigned long) rx_buffer;

    ret = ioctl(spi->spi_dev_fd, SPI_IOC_MESSAGE(1), &spi->spi_transfer);
    FATAL_ON(ret != (int) spi->spi_transfer.len);
  }

  // Make sure the start and length byte make sense
  {
    if (rx_buffer[0] != START_BTL_FRAME) {
      TRACE_EZSP_SPI("[send frame] FAIL : Wrong start of frame. Received 0x%x, expected 0x%x", rx_buffer[0], START_BTL_FRAME);

      de_assert_cs(spi);

      return SL_STATUS_FAIL;
    }

    uint8_t payload_length = rx_buffer[1];

    if (payload_length != 1) {
      TRACE_EZSP_SPI("[send frame] FAIL : Wrong reply length. Got %" PRIu8 " expected 1", payload_length);

      // The length is wrong, bring back CS high and bail
      de_assert_cs(spi);

      return SL_STATUS_FAIL;
    }
  }

  // Based on the length, read the rest of the reply
  {
    spi->spi_transfer.len = rx_buffer[1] + 1u;
    spi->spi_transfer.cs_change = 0; // De-assert CS
    spi->spi_transfer.tx_buf = (unsigned long) NULL;
    spi->spi_transfer.rx_buf = (unsigned long) &rx_buffer[2];

    ret = ioctl(spi->spi_dev_fd, SPI_IOC_MESSAGE(1), &spi->spi_transfer);
    FATAL_ON(ret != (int) spi->spi_transfer.len);
  }

  // Make sure the reply is good
  {
    if (rx_buffer[spi->spi_transfer.len + 1] != END_BTL_FRAME) {
      TRACE_EZSP_SPI("[send frame] FAIL : Wrong end of frame. Received 0x%x, expected 0x%x", rx_buffer[spi->spi_transfer.len + 2], END_BTL_FRAME);

      return SL_STATUS_FAIL;
    }

    uint8_t response = rx_buffer[2];

    if (response != EZSP_SPI_FRAME_BTL_BLOCKOK) {
      TRACE_EZSP_SPI("[send frame] FAIL : Reply. Received %s, expected %s", ezsp_spi_frame_to_str(response), ezsp_spi_frame_to_str(EZSP_SPI_FRAME_BTL_BLOCKOK));

      return SL_STATUS_FAIL;
    }
  }

  // Wait on IRQ asserted to pull the XMODEM ACK
  {
    status = wait_irq_falling_edge(spi, IRQ_FALLING_EDGE_TIMEOUT_MS);

    if (status == SL_STATUS_TIMEOUT) {
      TRACE_EZSP_SPI("[send frame] FAIL : IRQ falling-edge timeout for xmodem ack");

      // command failed because of timeout
      return SL_STATUS_TIMEOUT;
    }
  }

  gpio_clear_irq(spi->irq_gpio);

  // Read the XMODEM ACK packet
  {
    status = send_command_with_retries(spi, EZSP_SPI_FRAME_BTL_QUERY, rx_buffer);

    if (status != SL_STATUS_OK) {
      TRACE_EZSP_SPI("[send frame] FAIL : receiving XMODEM ACK");

      return SL_STATUS_FAIL;
    }

    if (rx_buffer[2] != XMODEM_CMD_ACK) {
      TRACE_EZSP_SPI("[send frame] FAIL : reply is not an ACK");

      return SL_STATUS_FAIL;
    }
  }

  // Confirm the XMODEM ACK's sequence number is good
  {
    const uint8_t sent_seq = spi_xmodem_buffer->frame.seq;
    const uint8_t recv_seq = rx_buffer[3];

    if (sent_seq != recv_seq) {
      TRACE_EZSP_SPI("[send frame] FAIL : reply is not an ACK");

      return SL_STATUS_FAIL;
    }
  }

  return SL_STATUS_OK;
}

static sl_status_t send_frame_with_retries(struct spi_interface *spi, struct spi_xmodem_buffer *spi_xmodem_buffer, size_t retries)
{
  sl_status_t status = SL_STATUS_FAIL;

  while (retries--) {
    status = send_frame(spi, spi_xmodem_buffer);

    if (status == SL_STATUS_OK) {
      return SL_STATUS_OK;
    }
  }

  return status;
}

static sl_status_t firmware_upgrade_fsm(struct fwu_image *image,
                                        struct spi_interface *spi)
{
  sl_status_t status;
  struct spi_xmodem_buffer spi_xmodem_buffer = {
    .start = START_BTL_FRAME,
    .size = sizeof(XmodemFrame_t),
    .frame = {
      .header = XMODEM_CMD_SOH,
      .seq = 0,
    },
    .end = END_BTL_FRAME
  };
  // Due to the nature of the half-duplex EZSP protocol, the data[128] field of the XMODEM transmission buffer
  // can be reused for the reception of the responses to save on memory.
  uint8_t * const spi_rx_buffer = spi_xmodem_buffer.frame.data;

  // If the firmware upgrade was initiated with the daemon speaking CPC to ask the
  // secondary to reboot into bootloader mode, it means this state machine was
  // called shortly after we had the confirmation from the secondary that it was
  // going to reset. IRQ line will go from HIGI to LOW as the secondary reboots and
  // cuts power to the pin. This will produce a falling-edge event. This false event
  // needs to be cleared. In about typically 20ms from now, the secondary will have rebooted
  // in bootloader mode
  if (config.fwu_recovery_pins_enabled == false && !ezsp_spi_is_bootloader_running(NULL, 0, NULL, 0)) {
    #ifndef USE_LEGACY_GPIO_SYSFS
    // Clearing the aforementioned false falling-edge event
    gpio_clear_irq(spi->irq_gpio);
    #endif

    TRACE_EZSP_SPI("Waiting for the bootloader to boot and produce an initial IRQ falling-edge");

    // The secondary will produce an IRQ falling-edge in about 20ms when the bootloader
    // wakes up, configures its pin (high) and then bring it low to signal it wants to send
    // its reboot reason
    status = wait_irq_falling_edge(spi, IRQ_FALLING_EDGE_TIMEOUT_MS);

    if (status == SL_STATUS_TIMEOUT) {
      if (gpio_read(spi->irq_gpio) == GPIO_VALUE_HIGH) {
        TRACE_EZSP_SPI("[FAIL] timeout");
        return SL_STATUS_TIMEOUT;
      } else {
        // On Series 1, the chip reset occurring when asking to reboot into bootloader
        // seems to reset the GPIO peripheral way earlier than Series 2, resulting
        // in the IRQ falling-edge happening before the SPI driver closes the IRQ
        // pin and this EZSP driver opening it. This results in the event being lost.
        // By doing a second check after the timeout, if the pin is low we can assume
        // that the falling-edge occurred and it was just missed.
      }
    }

    gpio_clear_irq(spi->irq_gpio);

    TRACE_EZSP_SPI("[OK]");

    // Waiting 100 us to give some time to the bootloader to initialize the EZSP protocol
    sleep_us(100);
  }

  // The bootloader starts by sending its reboot reason. It needs to be pulled first
  {
    TRACE_EZSP_SPI("Pulling the bootloader reset reason");

    status = pull_reset_reason_or_spi_status_with_retries(spi);

    if (status != SL_STATUS_OK) {
      TRACE_EZSP_SPI("[FAIL]");
      return status;
    }

    TRACE_EZSP_SPI("[OK]");
  }

  // Send a QUERY command and receive a QUERYFOUND reply.
  // This step is necessary to establish a communication with the bootloader and
  // place it in a mode where it will accept a firmware image
  {
    TRACE_EZSP_SPI("Sending initial QUERY command");

    status = send_command_with_retries(spi, EZSP_SPI_FRAME_BTL_QUERY, spi_rx_buffer);

    if (status != SL_STATUS_OK) {
      TRACE_EZSP_SPI("[FAIL]");
      return status;
    }

    // The reply of the first query command is the QUERYFOUND reply
    uint8_t response = spi_rx_buffer[2];

    if (response != EZSP_SPI_FRAME_BTL_QUERYFOUND) { // The 3rd byte of the RX buffer is the reply opcode
      TRACE_EZSP_SPI("FAIL : Received %s, expected %s", ezsp_spi_frame_to_str(response), ezsp_spi_frame_to_str(EZSP_SPI_FRAME_BTL_QUERYFOUND));

      return SL_STATUS_FAIL;
    }

    TRACE_EZSP_SPI("[OK]");
  }

  // After the first QUERY command transaction, the bootloader will pull IRQ low
  // shortly after to signal us to perform another the QUERY transaction.
  {
    TRACE_EZSP_SPI("Waiting for IRQ falling-edge event following the first QUERY");

    status = wait_irq_falling_edge(spi, IRQ_FALLING_EDGE_TIMEOUT_MS);

    if (status == SL_STATUS_TIMEOUT) {
      TRACE_EZSP_SPI("[FAIL] Timeout waiting for the IRQ falling-edge event");
      return SL_STATUS_TIMEOUT;
    }

    TRACE_EZSP_SPI("[OK]");
  }

  // Send a second QUERY command.
  // Instead of a QUERYFOUND reply, a QUERYRESP containing some info will be
  // received. The data is useless for this state machine; nonetheless, it has to be pulled.
  {
    TRACE_EZSP_SPI("Sending the second QUERY command");

    status = send_command_with_retries(spi, EZSP_SPI_FRAME_BTL_QUERY, spi_rx_buffer);

    if (status != SL_STATUS_OK) {
      TRACE_EZSP_SPI("[FAIL]");
      return status;
    }

    TRACE_EZSP_SPI("[OK]");

    // Copied from the spi bootloader source code
    typedef struct {
      uint8_t btlCommand;
      uint8_t btlActive;
      uint8_t manufacturerId[2];
      uint8_t hardwareTag[16];
      uint8_t btlCapabilities;
      uint8_t platform;
      uint8_t micro;
      uint8_t phy;
      uint8_t btlMajorVersion;
      uint8_t btlMinorVersion;
    } __attribute__((packed)) EzspSpiQueryResponse_t;

    const EzspSpiQueryResponse_t *response = (EzspSpiQueryResponse_t*) &spi_rx_buffer[2];

    if (spi_rx_buffer[1] != sizeof(EzspSpiQueryResponse_t)) {
      TRACE_EZSP_SPI("Strange.. the size of the reply to the second QUERY command is not equal to a EzspSpiQueryResponse_t struct. Moving on ...");
    } else if (response->btlCommand != EZSP_SPI_FRAME_BTL_QUERYRESP) {
      TRACE_EZSP_SPI("Strange.. The reply is not a QUERYRESP. Moving on ...");
    } else {
      TRACE_EZSP_SPI("Bootloader major version : %" PRIu8, response->btlMajorVersion);
      TRACE_EZSP_SPI("Bootloader minor version : %" PRIu8, response->btlMinorVersion);
    }
  }

  // The bootloader is now ready to receive an image, send the firmware image
  {
    TRACE_EZSP_SPI("Sending the firmware image :");
    TRACE(" ");

    size_t remaining_len = image->size;
    size_t data_index = 0;

    while (remaining_len) {
      size_t frame_size = min(remaining_len, sizeof(spi_xmodem_buffer.frame.data));

      remaining_len -= frame_size;

      memcpy(spi_xmodem_buffer.frame.data, &image->data[data_index], frame_size);
      // 0x1A padding if last frame
      memset(spi_xmodem_buffer.frame.data + frame_size, 0x1A, sizeof(spi_xmodem_buffer.frame.data) - frame_size);

      data_index += frame_size;

      spi_xmodem_buffer.frame.seq++;
      spi_xmodem_buffer.frame.seq_neg = (uint8_t)(0xff - spi_xmodem_buffer.frame.seq);

      u16_to_be(sli_cpc_get_crc_sw(spi_xmodem_buffer.frame.data, sizeof(spi_xmodem_buffer.frame.data)), (uint8_t *)&spi_xmodem_buffer.frame.crc);

      status = send_frame_with_retries(spi, &spi_xmodem_buffer, MAX_RETRANSMIT_ATTEMPTS);

      if (status != SL_STATUS_OK) {
        TRACE_EZSP_SPI("[FAIL] too many attempts at sending frame");
        return status;
      }

      TRACE_NAKED(".");

      if (data_index % (20 * 128) == 0) {
        TRACE_NAKED("\n");
        TRACE(" ");
      }
    }

    TRACE_NAKED("OK\n");
  }

  // Send XMODEM EOT command
  {
    TRACE_EZSP_SPI("Sending End-Of-Transfer command");

    status = send_command_with_retries(spi, XMODEM_CMD_EOT, spi_rx_buffer);

    if (status != SL_STATUS_OK) {
      TRACE_EZSP_SPI("[FAIL]");
      return status;
    }

    uint8_t response = spi_rx_buffer[2];

    if (response != EZSP_SPI_FRAME_BTL_FILEDONE) { // The 3rd byte of the RX buffer is the reply opcode
      TRACE_EZSP_SPI("FAIL : Received %s, expected %s", ezsp_spi_frame_to_str(response), ezsp_spi_frame_to_str(EZSP_SPI_FRAME_BTL_FILEDONE));

      return SL_STATUS_FAIL;
    }

    TRACE_EZSP_SPI("[OK]");
  }

  {
    TRACE_EZSP_SPI("Waiting for IRQ falling-edge event following EOT command");

    status = wait_irq_falling_edge(spi, IRQ_FALLING_EDGE_TIMEOUT_MS);

    if (status != SL_STATUS_OK) {
      TRACE_EZSP_SPI("[FAIL] Timeout waiting for the IRQ falling-edge event");
      return status;
    }

    TRACE_EZSP_SPI("[OK]");
  }

  // Confirm EOT command
  {
    TRACE_EZSP_SPI("Confirming End-Of-Transfer");

    status = send_command_with_retries(spi, EZSP_SPI_FRAME_BTL_QUERY, spi_rx_buffer);

    if (status != SL_STATUS_OK) {
      TRACE_EZSP_SPI("[FAIL]");
      return status;
    }

    uint8_t response = spi_rx_buffer[2];

    if (response != XMODEM_CMD_ACK) { // The 3rd byte of the RX buffer is the reply opcode
      TRACE_EZSP_SPI("FAIL : Received 0x%x, expected XMODEM_CMD_ACK", response);

      return SL_STATUS_FAIL;
    }

    TRACE_EZSP_SPI("[OK]");
  }

  {
    TRACE_EZSP_SPI("Waiting for IRQ falling-edge event signaling a reboot");

    status = wait_irq_falling_edge(spi, IRQ_FALLING_EDGE_TIMEOUT_MS);

    if (status == SL_STATUS_TIMEOUT) {
      TRACE_EZSP_SPI("[WARNING] timeout");
    } else {
      TRACE_EZSP_SPI("[OK]");
    }

    gpio_clear_irq(spi->irq_gpio);
  }

  {
    TRACE_EZSP_SPI("Waiting for IRQ falling-edge event signaling CPC bootup");

    status = wait_irq_falling_edge(spi, IRQ_FALLING_EDGE_TIMEOUT_MS);

    if (status == SL_STATUS_TIMEOUT) {
      TRACE_EZSP_SPI("[WARNING] timeout");
    } else {
      TRACE_EZSP_SPI("[OK]");
    }
  }

  return SL_STATUS_OK;
}

sl_status_t ezsp_spi_firmware_upgrade(const char   *image_file,
                                      const char   *device,
                                      unsigned int  bitrate,
                                      const char   *irq_gpio_chip,
                                      unsigned int  irq_gpio_pin)
{
  sl_status_t status = SL_STATUS_OK;
  struct fwu_image image;
  struct spi_interface spi;

  TRACE_EZSP_SPI("Opening EZSP interface...");

  // open connection to secondary
  open_spi_interface(device, bitrate, irq_gpio_chip, irq_gpio_pin, &spi);

  TRACE_EZSP_SPI("EZSP interface opened successfully.");

  open_fwu_image(image_file, &image);

  TRACE_EZSP_SPI("Starting the firmware upgrade FSM");

  status = firmware_upgrade_fsm(&image, &spi);

  TRACE_EZSP_SPI("Exited the firmware upgrade FSM with status : %d", status);

  close_spi_interface(&spi);
  close_fwu_image(&image);

  return status;
}

/***************************************************************************//**
 * @brief
 *   Probes the secondary to see if the bootloader is running
 *
 * The goal of the probe maneuver is to detect if the secondary is currently
 * running the bootloader or not (else the CPC application, or perhaps nothing).
 *
 * There is an important detail to keep in mind : The SPI driver on the secondary
 * is very susceptible to deadlocking if the CPC SPI protocol is not strictly
 * followed. This means that if the secondary is currently running the CPC app and
 * we start sending things (i.e. talking EZSP-bootloader protocol to probe the
 * bootloader) on the SPI bus that do not follow the CPC-SPI protocol, we will
 * make the secondary driver fall out of sync, requiring a reboot.
 *
 * This function therefore sends what is essentially a CPC SPI Header in term
 * of electrical signal - ie 7 bytes - that would not make the CPC SPI driver
 * jam, but that header is also a valid EZSP transaction that the bootloader
 * would recognize as a probe. This way, no matter what the secondary is currently
 * running, it won't brick.
 *
 * @return
 *   true if the bootloader is running, false otherwise
 ******************************************************************************/
bool ezsp_spi_is_bootloader_running(const char *device,
                                    unsigned int bitrate,
                                    const char *irq_gpio_chip,
                                    unsigned int irq_gpio_pin)
{
  static bool bootloader_probed = false;
  static bool bootloader_alive = false;
  struct spi_ioc_transfer spi_transfer = { 0 };
  uint8_t rx_buffer[7];
  int ret;
  struct spi_interface spi;

  if (bootloader_probed == true) {
    return bootloader_alive;
  } else {
    bootloader_probed = true;
  }
  // open connection to secondary
  open_spi_interface(device, bitrate, irq_gpio_chip, irq_gpio_pin, &spi);

  gpio_clear_irq(spi.irq_gpio);

  // Always go with a conservative value of 1MHz for the probing sequence
  spi_transfer.speed_hz = 1000000;

  // Send the SPI status bootloader command
  // and keep CS asserted at the end of the transfer
  {
    const uint8_t spi_status_tx_buffer[2] = { SPI_STATUS, END_BTL_FRAME };

    spi_transfer.tx_buf = (unsigned long) spi_status_tx_buffer;
    spi_transfer.rx_buf = (unsigned long) &rx_buffer[0];
    spi_transfer.len = sizeof(spi_status_tx_buffer);
    spi_transfer.cs_change = 1; // Keep CS asserted after the transfer per EZSP

    ret = ioctl(spi.spi_dev_fd, SPI_IOC_MESSAGE(1), &spi_transfer);
    FATAL_ON(ret != (int)spi_transfer.len);
  }

  // Worse case scenario is 600us for a bootloader reset reason, give 1ms timeout
  (void) wait_irq_falling_edge(&spi, 1);

  // Clock 5 more 0x00 bytes and de-assert CS.
  {
    spi_transfer.tx_buf = (unsigned long) NULL;
    spi_transfer.rx_buf = (unsigned long) &rx_buffer[2];
    spi_transfer.len = 5;
    spi_transfer.cs_change = 0; // De-assert CS after transfer

    ret = ioctl(spi.spi_dev_fd, SPI_IOC_MESSAGE(1), &spi_transfer);
    FATAL_ON(ret != (int)spi_transfer.len);
  }

  // Analyze the receive buffer to see if a valid bootloader response is detected
  {
    // There are 3 possible responses the bootloader could reply to the SPI-Status command
    const uint8_t btl_response_reset_reason[]  = { 0xFF, 0xFF, 0x00, 0x09, END_BTL_FRAME, 0xFF, 0xFF };
    const uint8_t btl_response_spi_status[]    = { 0xFF, 0xFF, 0xC1, END_BTL_FRAME, 0xFF, 0xFF, 0xFF };
    const uint8_t btl_response_spi_status2[]   = { 0xFF, 0xFF, 0xC0, END_BTL_FRAME, 0xFF, 0xFF, 0xFF };

    if (   0 == memcmp(rx_buffer, btl_response_reset_reason, sizeof(btl_response_reset_reason))
           || 0 == memcmp(rx_buffer, btl_response_spi_status, sizeof(btl_response_spi_status))
           || 0 == memcmp(rx_buffer, btl_response_spi_status2, sizeof(btl_response_spi_status2))) {
      // A positive bootloader response has been received. It is safe to return now without
      // purging a CPC payload. Since CPC is not running there is no risk of de-synchronizing the
      // SPI driver.
      bootloader_alive = true;
      goto ret;
    }
  }

  // At this point, we know the bootloader is NOT running.
  // It could still very well be CPC, or nothing.
  // Analyzing the header for a NULL header (i.e. 7 0s) is not a sufficient criteria to know whether CPC
  // is running or not. We cannot take the chance of stopping here and brick the driver,
  // we have to complete this operation as if it was a real CPC frame.

  // Analyze the received buffer to see if it was a CPC header the secondary sent us
  int header_len_field = hdlc_extract_payload_size(rx_buffer);

  if (header_len_field < 0) {
    // The header was not a valid CPC header. For the purpose or the procedure, treat it as if the length was 0
    header_len_field = 0;
  }

  (void) wait_irq_falling_edge(&spi, 1);

  // The secondary, if running CPC, expects the primary to clock out the payload
  {
    uint8_t *zero_buffer;

    // We don't care about the received data
    spi_transfer.rx_buf = (unsigned long) NULL;

    if (header_len_field > 0) {
      // If we did clock a valid CPC header with a payload length that was greater than 0,
      // we need to clock that number of bytes. We don't care about what we transmit nor
      // receive. rx_buf is already NULL, but we cannot set tx_buf to NULL as well, it needs
      // to be a valid buffer. Here we want to send all 0s.
      zero_buffer = calloc(1, (size_t)header_len_field);
      spi_transfer.tx_buf = (unsigned long) zero_buffer;
    } else {
      // Produce the CS empty notch
      spi_transfer.tx_buf = (unsigned long) NULL;
    }

    spi_transfer.len = (unsigned) header_len_field;
    spi_transfer.cs_change = 0;

    ret = ioctl(spi.spi_dev_fd, SPI_IOC_MESSAGE(1), &spi_transfer);
    FATAL_ON(ret != (int)spi_transfer.len);

    if (header_len_field > 0) {
      free(zero_buffer);
    }
  }

  ret:
  close_spi_interface(&spi);

  return bootloader_alive;
}
