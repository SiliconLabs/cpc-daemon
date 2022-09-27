/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Config Interface
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

#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <sys/resource.h>

#ifndef DEFAULT_INSTANCE_NAME
  #define DEFAULT_INSTANCE_NAME "cpcd_0"
#endif

#ifndef DEFAULT_SOCKET_FOLDER
  #define DEFAULT_SOCKET_FOLDER "/dev/shm"
#endif

#ifndef DEFAULT_CONFIG_FILE_PATH
  #define DEFAULT_CONFIG_FILE_PATH "/etc/cpcd.conf"
#endif

typedef enum {
  UART,
  SPI,
  UNCHOSEN
}bus_t;

typedef enum {
  MODE_NORMAL,
  MODE_BINDING_UNKNOWN,
  MODE_BINDING_ECDH,
  MODE_BINDING_PLAIN_TEXT,
  MODE_BINDING_UNBIND,
  MODE_FIRMWARE_UPDATE,
  MODE_UART_VALIDATION
}operation_mode_t;

typedef struct __attribute__((packed)) {
  const char *file_path;

  const char *instance_name;

  const char *const socket_folder;

  operation_mode_t operation_mode;

  bool use_encryption;

  const char *binding_key_file;

  const char *binding_method;

  bool stdout_tracing;
  bool file_tracing;
  int lttng_tracing;
  bool enable_frame_trace;
  const char *traces_folder;

  bus_t bus;

  unsigned int uart_baudrate;
  bool uart_hardflow;
  const char *uart_file;

  const char *spi_file;
  unsigned int spi_bitrate;
  unsigned int spi_mode;
  unsigned int spi_bit_per_word;
  const char *spi_cs_chip;
  unsigned int spi_cs_pin;
  const char *spi_irq_chip;
  unsigned int spi_irq_pin;

  const char *fu_reset_chip;
  unsigned int fu_spi_reset_pin;
  const char *fu_wake_chip;
  unsigned int fu_spi_wake_pin;
  bool fu_recovery_enabled;
  bool fu_connect_to_bootloader;
  bool fu_enter_bootloader;
  const char *fu_file;
  bool fu_restart_daemon;

  const char *board_controller_ip_addr;

  const char *application_version_validation;

  bool print_secondary_versions_and_exit;

  bool use_noop_keep_alive;

  bool reset_sequence;

  const char *uart_validation_test_option;

  long stats_interval;

  rlim_t rlimit_nofile;
} config_t;

extern config_t config;

void config_init(int argc, char *argv[]);
void config_restart_cpcd();
void config_restart_cpcd_without_fw_update_args(void);

#endif //CONFIG_H
