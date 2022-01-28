/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - EZSP-SPI driver
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

#include "server_core/core/crc.h"
#include "driver/driver_spi.h"
#include "driver/driver_ezsp.h"
#include "misc/logging.h"
#include "misc/xmodem.h"

#define  START_BTL_FRAME   0xFD
#define  END_BTL_FRAME     0xA7
#define  SPI_STATUS        0x0B
#define  SPI_VERSION       0x0A

#define  BOOTLOADER_TIMEOUT  10

#define TIMEOUT     0x16
#define FILEDONE    0x17
#define FILEABORT   0x18
#define BLOCKOK     0x19
#define QUERY       0x51
#define QUERYFOUND  0x1A

#define SPI_BUFFER_SIZE  4096

static cpc_spi_dev_t spi_dev;

static struct spi_ioc_transfer spi_tranfer;

static uint8_t rx_spi_buffer[SPI_BUFFER_SIZE];
static uint8_t tx_spi_buffer[SPI_BUFFER_SIZE];

static int read_until_end_of_frame(void);
static bool wait_irq_line(void);
static int get_spi_version(void);
static int get_spi_status(void);;
static int send_query(void);
static bool send_end_of_file(void);
static bool ezsp_send_bootloader_raw_bytes(const uint8_t *message, uint8_t length);
static void cs_assert(void);
static void cs_deassert(void);

static void driver_ezsp_spi_open(const char *device,
                                 unsigned int mode,
                                 unsigned int bit_per_word,
                                 unsigned int speed,
                                 unsigned int cs_gpio_number,
                                 unsigned int irq_gpio_number,
                                 unsigned int wake_gpio_number);

int send_firmware(const char* image_file,
                  const char *device,
                  unsigned int mode,
                  unsigned int bit_per_word,
                  unsigned int speed,
                  unsigned int cs_gpio,
                  unsigned int irq_gpio,
                  unsigned int wake_gpio)
{
  struct stat stat;
  int ret = 0;
  int image_file_fd;
  uint8_t* mmaped_image_file_data;
  size_t mmaped_image_file_len;
  unsigned int retransmit_count = 0;

  driver_ezsp_spi_open(device,
                       mode,
                       bit_per_word,
                       speed,
                       cs_gpio,
                       irq_gpio,
                       wake_gpio);

  // AN1084 Section 2.2
  get_spi_status();
  get_spi_status();
  get_spi_version();

  if (send_query() == QUERYFOUND) {
    send_query();
  }

  image_file_fd = open(image_file, O_RDONLY | O_CLOEXEC);
  FATAL_SYSCALL_ON(image_file_fd < 0);

  fstat(image_file_fd, &stat);

  mmaped_image_file_len = (size_t) stat.st_size;

  mmaped_image_file_data = mmap(NULL, mmaped_image_file_len, PROT_READ, MAP_PRIVATE, image_file_fd, 0);
  FATAL_SYSCALL_ON(mmaped_image_file_data == NULL);

  XmodemFrame_t frame;
  uint8_t* image_file_data = mmaped_image_file_data;
  size_t image_file_len = mmaped_image_file_len;

  frame.header = XMODEM_CMD_SOH;
  frame.seq = 1; //Sequence number starts at one initially, wraps around to 0 afterward

  TRACE_EZSP_SPI("Starting SPI bootloading...");

  while (image_file_len) {
    size_t z = 0;
    bool proceed_to_next_frame = false;
    char status;

    z = min(image_file_len, sizeof(frame.data));

    memcpy(frame.data, image_file_data, z);
    memset(frame.data + z, 0xff, sizeof(frame.data) - z);

    frame.crc = __builtin_bswap16(sli_cpc_get_crc_sw(frame.data, sizeof(frame.data)));

    frame.seq_neg = (uint8_t)(0xff - frame.seq);

    proceed_to_next_frame = ezsp_send_bootloader_raw_bytes((const uint8_t *)&frame, sizeof(frame));

    if (proceed_to_next_frame) {
      frame.seq++;
      image_file_len -= z;
      image_file_data += z;
      status = '.';
    } else {
      status = 'N';
      retransmit_count++;
    }

    trace_no_timestamp("%c", status);
  }

  trace_no_timestamp("\n");

  if (send_end_of_file()) {
    TRACE_EZSP_SPI("Transfer of file \"%s\" completed with %u retransmits.", image_file, retransmit_count);
  } else {
    TRACE_EZSP_SPI("Transfer of file failed");
  }

  send_query();

  sleep(1);

  ret = munmap(mmaped_image_file_data, mmaped_image_file_len);
  FATAL_SYSCALL_ON(ret != 0);

  ret = close(image_file_fd);
  FATAL_SYSCALL_ON(ret != 0);

  ret = close(spi_dev.spi_dev_descriptor);
  FATAL_SYSCALL_ON(ret != 0);

  PRINT_INFO("Firmware upgrade successfull. Exiting, restart CPCd without -f option.\n");

  exit(EXIT_SUCCESS);

  return 0;
}

static void driver_ezsp_spi_open(const char *device,
                                 unsigned int mode,
                                 unsigned int bit_per_word,
                                 unsigned int speed,
                                 unsigned int cs_gpio_number,
                                 unsigned int irq_gpio_number,
                                 unsigned int wake_gpio_number)
{
  int ret = 0;
  int fd;

  mode |= SPI_NO_CS;

  memset(&spi_tranfer, 0, sizeof(struct spi_ioc_transfer));

  // SPIDEV0: MOSI (GPIO10); MISO (GPIO9); SCLK (GPIO11); RX_IRQ (GPIO23); CS (GPIO24)
  fd = open(device, O_RDWR | O_CLOEXEC);
  FATAL_SYSCALL_ON(fd < 0);

  ret = ioctl(fd, SPI_IOC_WR_MODE, &mode);
  FATAL_SYSCALL_ON(ret < 0);

  ret = ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bit_per_word);
  FATAL_SYSCALL_ON(ret < 0);

  spi_tranfer.bits_per_word = (uint8_t)bit_per_word;

  ret = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
  FATAL_SYSCALL_ON(ret < 0);

  spi_tranfer.speed_hz = speed;

  spi_tranfer.rx_buf = (unsigned long)rx_spi_buffer;
  spi_tranfer.tx_buf = (unsigned long)tx_spi_buffer;

  spi_dev.spi_dev_descriptor = fd;

  // Setup CS gpio
  FATAL_ON(gpio_init(&spi_dev.cs_gpio, cs_gpio_number) < 0);
  FATAL_ON(gpio_direction(spi_dev.cs_gpio, OUT) < 0);
  FATAL_ON(gpio_write(spi_dev.cs_gpio, 1) < 0);

  // Setup WAKE gpio
  FATAL_ON(gpio_init(&spi_dev.wake_gpio, wake_gpio_number) < 0);
  FATAL_ON(gpio_direction(spi_dev.wake_gpio, OUT) < 0);
  FATAL_ON(gpio_write(spi_dev.wake_gpio, 1) < 0);

  // Setup IRQ gpio
  FATAL_ON(gpio_init(&spi_dev.irq_gpio, irq_gpio_number) < 0);
  FATAL_ON(gpio_direction(spi_dev.irq_gpio, IN) < 0);
}

static int read_until_end_of_frame(void)
{
  uint8_t temp_array[SPI_BUFFER_SIZE];
  uint16_t cpt = 0;
  int ret = 0;
  int timeout = BOOTLOADER_TIMEOUT;

  memset(tx_spi_buffer, 0xFF, SPI_BUFFER_SIZE);
  memset(rx_spi_buffer, 0, SPI_BUFFER_SIZE);

  spi_tranfer.len = 1u;

  ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_tranfer);
  FATAL_ON(ret != 1);

  temp_array[cpt++] = rx_spi_buffer[0];

  while (rx_spi_buffer[0] != END_BTL_FRAME
         && timeout > 0) {
    ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_tranfer);
    FATAL_ON(ret != 1);
    temp_array[cpt++] = rx_spi_buffer[0];
    timeout--;
  }

  if (timeout == 0) {
    return -1;
  }

  memcpy(rx_spi_buffer, temp_array, cpt);

  return cpt;
}

static bool wait_irq_line(void)
{
  int timeout = 3;

  while ((gpio_read(spi_dev.irq_gpio) != 0)
         || timeout-- < 0) {
    usleep(10);
  }

  if (timeout == 0) {
    return false;
  }

  return true;
}

static int get_spi_status(void)
{
  int ret = 0;

  memset(tx_spi_buffer, 0xFF, SPI_BUFFER_SIZE);
  memset(rx_spi_buffer, 0, SPI_BUFFER_SIZE);

  // [0B A7]
  spi_tranfer.len = 2u;

  tx_spi_buffer[0] = SPI_STATUS;
  tx_spi_buffer[1] = END_BTL_FRAME;

  cs_assert();
  ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_tranfer);
  FATAL_ON(ret != 2);

  if (!wait_irq_line()) {
    cs_deassert();
    return -1;
  }

  ret = read_until_end_of_frame();

  cs_deassert();

  usleep(1000);

  return rx_spi_buffer[2];
}

static int get_spi_version(void)
{
  int ret = 0;

  memset(tx_spi_buffer, 0xFF, SPI_BUFFER_SIZE);
  memset(rx_spi_buffer, 0, SPI_BUFFER_SIZE);

  // [0A A7]
  spi_tranfer.len = 2u;

  tx_spi_buffer[0] = SPI_VERSION;
  tx_spi_buffer[1] = END_BTL_FRAME;

  cs_assert();
  ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_tranfer);
  FATAL_ON(ret != 2);

  if (!wait_irq_line()) {
    cs_deassert();
    return -1;
  }

  ret = read_until_end_of_frame();

  cs_deassert();

  usleep(1000);

  return rx_spi_buffer[2];
}

static int send_query(void)
{
  int ret = 0;

  memset(tx_spi_buffer, 0xFF, SPI_BUFFER_SIZE);
  memset(rx_spi_buffer, 0, SPI_BUFFER_SIZE);

  // [FD 01 51 A7]
  spi_tranfer.len = 4u;

  tx_spi_buffer[0] = 0xFD;
  tx_spi_buffer[1] = 0x01;
  tx_spi_buffer[2] = QUERY;
  tx_spi_buffer[3] = END_BTL_FRAME;

  cs_assert();
  ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_tranfer);
  FATAL_ON(ret != 4);

  if (!wait_irq_line()) {
    cs_deassert();
    return -1;
  }

  ret = read_until_end_of_frame();

  cs_deassert();

  usleep(1000);

  return rx_spi_buffer[2];
}

static bool send_end_of_file(void)
{
  int ret = 0;

  memset(tx_spi_buffer, 0xFF, SPI_BUFFER_SIZE);
  memset(rx_spi_buffer, 0, SPI_BUFFER_SIZE);

  spi_tranfer.len = 4u;

  // [FD 01 04 A7]
  tx_spi_buffer[0] = START_BTL_FRAME;
  tx_spi_buffer[1] = 0x01;
  tx_spi_buffer[2] = XMODEM_CMD_EOT;
  tx_spi_buffer[3] = END_BTL_FRAME;

  cs_assert();

  ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_tranfer);
  FATAL_ON(ret != 4);

  if (!wait_irq_line()) {
    cs_deassert();
    return -1;
  }

  ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_tranfer);
  FATAL_ON(ret != 4);

  cs_deassert();

  usleep(1000);

  if (rx_spi_buffer[2] == FILEDONE) {
    return true;
  }

  return false;
}

static bool ezsp_send_bootloader_raw_bytes(const uint8_t *message, uint8_t length)
{
  int ret = 0;

  memset(tx_spi_buffer, 0xFF, SPI_BUFFER_SIZE);
  memset(rx_spi_buffer, 0, SPI_BUFFER_SIZE);

  // Build ezsp frame
  tx_spi_buffer[0] = START_BTL_FRAME;
  tx_spi_buffer[1] = length;
  memcpy((void *)&tx_spi_buffer[2], message, length);
  tx_spi_buffer[length + 2] = END_BTL_FRAME;

  spi_tranfer.len = length + 3u;

  cs_assert();

  ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_tranfer);
  FATAL_ON(ret != (int)(length) + 3);

  if (!wait_irq_line()) {
    cs_deassert();
    return false;
  }

  // [FD 01 19 A7]
  spi_tranfer.len = 4u;
  ret = ioctl(spi_dev.spi_dev_descriptor, SPI_IOC_MESSAGE(1), &spi_tranfer);
  FATAL_ON(ret != 4u);

  cs_deassert();

  usleep(1000);

  if (rx_spi_buffer[2] == BLOCKOK) {
    return true;
  }

  return false;
}

static void cs_assert(void)
{
  int ret = 0;

  ret = gpio_write(spi_dev.cs_gpio, 0);
  FATAL_SYSCALL_ON(ret < 0);
}

static void cs_deassert(void)
{
  int ret = 0;

  ret = gpio_write(spi_dev.cs_gpio, 1);
  FATAL_SYSCALL_ON(ret < 0);
}
