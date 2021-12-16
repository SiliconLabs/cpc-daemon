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
  MODE_BINDING_PLAIN_TEXT,
  MODE_FIRMWARE_UPDATE
}operation_mode_t;

extern bus_t         config_bus;

extern int           config_stdout_tracing;
extern int           config_file_tracing;
extern int           config_lttng_tracing;

extern bool          config_use_noop_keep_alive;
extern bool          config_use_encryption;

extern const char*   config_traces_folder;

extern unsigned int  config_uart_baudrate;
extern bool          config_uart_hardflow;
extern const char*   config_uart_file;

extern const char*   config_spi_file;
extern unsigned int  config_spi_bitrate;
extern unsigned int  config_spi_mode;
extern unsigned int  config_spi_bit_per_word;
extern unsigned int  config_spi_cs_pin;
extern unsigned int  config_spi_irq_pin;
extern unsigned int  config_spi_wake_pin;

extern const char* const  config_socket_folder;
extern const char*   config_instance_name;

extern bool          config_reset_sequence;

extern operation_mode_t config_operation_mode;

extern const char*   config_binding_key_file;
extern const char*   config_fu_file;

void config_init(int argc, char *argv[]);

#endif //CONFIG_H
