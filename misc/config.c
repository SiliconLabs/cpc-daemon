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

#include "config.h"

#include <sys/resource.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <linux/spi/spidev.h>

#include "log.h"
#include "version.h"

/*******************************************************************************
 **********************  GLOBAL CONFIGURATION VALUES   *************************
 ******************************************************************************/
int           config_stdout_tracing = 0;
int           config_file_tracing = 0;
const char *  config_traces_folder = "./cpcd-traces";

bool          config_use_noop_keep_alive = false;

bus_t         config_bus = UNCHOSEN;

// UART config
unsigned int  config_uart_baudrate = 115200;
bool          config_uart_hardflow = false;
const char*   config_uart_file = NULL;

//SPI config
const char*   config_spi_file = NULL;
unsigned int  config_spi_bitrate = 1000000;
unsigned int  config_spi_mode = SPI_MODE_0;
unsigned int  config_spi_bit_per_word = 8;
unsigned int  config_spi_cs_pin = 24;
unsigned int  config_spi_irq_pin = 23;

const char*   config_socket_folder = "/tmp/";

bool          config_reset_sequence = true;

/*******************************************************************************
 **********************  LOCAL CONFIGURATION VALUES   **************************
 ******************************************************************************/

static const char* config_file_path = "/etc/cpcd.conf";

/*New number of concurrent opened file descriptor */
static rlim_t config_rlimit_nofile = 1024;

/*******************************************************************************
 **************************  LOCAL PROTOTYPES   ********************************
 ******************************************************************************/

static void config_print_version(FILE *stream, int exit_code);

static void config_print_help(FILE *stream, int exit_code);

static void config_parse_cli_arg(int argc, char *argv[]);

static void config_set_rlimit_nofile(void);

static void config_validate_configuration(void);

static void config_parse_config_file(void);

static const char* malloc_and_copy_str(const char* str);

/*******************************************************************************
 ****************************  IMPLEMENTATION   ********************************
 ******************************************************************************/
void config_init(int argc, char *argv[])
{
  config_parse_cli_arg(argc, argv);

  config_parse_config_file();

  config_validate_configuration();

  config_set_rlimit_nofile();
}

static void config_parse_cli_arg(int argc, char *argv[])
{
  static const struct option opt_list[] =
  {
    { "conf", required_argument, 0, 'c' },
    { "help", no_argument, 0, 'h' },
    { "version", no_argument, 0, 'v' },
    { 0, 0, 0, 0  }
  };

  int opt;

  while (1) {
    opt = getopt_long(argc, argv, "c:hv", opt_list, NULL);

    if (opt == -1) {
      break;
    }

    switch (opt) {
      case 0:
        break;
      case 'c':
        config_file_path = optarg;
        break;
      case 'h':
        config_print_help(stdout, 0);
        break;
      case 'v':
        config_print_version(stdout, 0);
        break;
      case '?':
      default:
        config_print_help(stderr, 1);
        break;
    }
  }
}

static bool is_comment_or_newline(const char* line)
{
  size_t line_size = strlen(line);

  if (line[0] == '\n') {
    return true;
  }

  size_t i;
  for (i = 0; i != line_size; i++) {
    if (line[i] == '#') {
      return true;
    }
  }

  return false;
}

static const char* malloc_and_copy_str(const char* str)
{
  char* s = malloc(strlen(str) + 1);

  (void)strcpy(s, str);

  return s;
}

static void config_parse_config_file(void)
{
  FILE *config_file;
  char name[128];
  char val[128];
  char line[256];
  char *endptr;

  config_file = fopen(config_file_path, "r");
  FATAL_SYSCALL_ON(config_file == NULL);

  /* Iterate through every line of the file*/
  while (fgets(line, sizeof(line), config_file) != NULL) {
    if (is_comment_or_newline(line)) {
      continue;
    }

    /* Exctract name=value pair */
    if (sscanf(line, "%127[^=]=%127[^\n]%*c", name, val) != 2) {
      WARN("Config file line \"%s\" doesn't respect syntax", line);
      continue;
    }

    if (0 == strcmp(name, "BUS_TYPE")) {
      if (0 == strcmp(val, "UART")) {
        config_bus = UART;
      } else if (0 == strcmp(val, "SPI")) {
        config_bus = SPI;
      } else {
        fprintf(stderr, "Config file error : bad BUS_TYPE value\n");
      }
      continue;
    }

    if (0 == strcmp(name, "SPI_DEVICE_FILE")) {
      config_spi_file = malloc_and_copy_str(val);
      continue;
    }

    if (0 == strcmp(name, "SPI_CS_GPIO")) {
      config_spi_cs_pin = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
      continue;
    }

    if (0 == strcmp(name, "SPI_RX_IRQ_GPIO")) {
      config_spi_irq_pin = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
      continue;
    }

    if (0 == strcmp(name, "SPI_DEVICE_BITRATE")) {
      config_spi_bitrate = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
      continue;
    }

    if (0 == strcmp(name, "UART_DEVICE_FILE")) {
      config_uart_file = malloc_and_copy_str(val);
      continue;
    }

    if (0 == strcmp(name, "UART_DEVICE_BAUD")) {
      config_uart_baudrate = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
      continue;
    }

    if (0 == strcmp(name, "UART_HARDFLOW")) {
      if (0 == strcmp(val, "true")) {
        config_uart_hardflow = true;
      } else if (0 == strcmp(val, "false")) {
        config_uart_hardflow = false;
      } else {
        fprintf(stderr, "Config file error : bad UART_HARDFLOW value\n");
      }
      continue;
    }

//TODO : evaluate if we would still like this to be configurable
/*
    if (0 == strcmp(name, "SOCKET_FOLDER")) {
      config_socket_folder = malloc_and_copy_str(val);
      continue;
    }

 */

    if (0 == strcmp(name, "NOOP_KEEP_ALIVE")) {
      if (0 == strcmp(val, "true")) {
        config_use_noop_keep_alive = true;
      } else if (0 == strcmp(val, "false")) {
        config_use_noop_keep_alive = false;
      } else {
        fprintf(stderr, "Config file error : bad NOOP_KEEP_ALIVE value\n");
      }
      continue;
    }

    if (0 == strcmp(name, "STDOUT_TRACE")) {
      if (0 == strcmp(val, "true")) {
        config_stdout_tracing = true;
      } else if (0 == strcmp(val, "false")) {
        config_stdout_tracing = false;
      } else {
        fprintf(stderr, "Config file error : bad STDOUT_TRACE value\n");
      }
      continue;
    }

    if (0 == strcmp(name, "TRACE_TO_FILE")) {
      if (0 == strcmp(val, "true")) {
        config_file_tracing = true;
      } else if (0 == strcmp(val, "false")) {
        config_file_tracing = false;
      } else {
        fprintf(stderr, "Config file error : bad TRACE_TO_FILE value\n");
      }
      continue;
    }

    if (0 == strcmp(name, "RESET_SEQUENCE")) {
      if (0 == strcmp(val, "true")) {
        config_reset_sequence = true;
      } else if (0 == strcmp(val, "false")) {
        config_reset_sequence = false;
      } else {
        fprintf(stderr, "Config file error : bad RESET_SEQUENCE value\n");
      }
      continue;
    }

    if (0 == strcmp(name, "TRACES_FOLDER")) {
      config_traces_folder = malloc_and_copy_str(val);
      continue;
    }

    if (0 == strcmp(name, "RLIMIT_NOFILE")) {
      config_rlimit_nofile = strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
      continue;
    }
  }

  fclose(config_file);
}

static void config_validate_configuration(void)
{
  if (config_bus != UART && config_bus != SPI) {
    FATAL("Bus selection is not UART or SPI");
  }

  if (config_bus == SPI) {
    if (config_spi_file == NULL) {
      FATAL("SPI device file missing");
    }
  }

  if (config_bus == UART) {
    if (config_uart_file == NULL) {
      FATAL("UART device file missing");
    }
  }
}

static void config_set_rlimit_nofile(void)
{
  struct rlimit limit;
  int ret;

  /* Make sure RLIMIT_NOFILE (number of concurrent opened file descriptor)
   * is at least config_rlimit_nofile  */

  ret = getrlimit(RLIMIT_NOFILE, &limit);
  FATAL_SYSCALL_ON(ret < 0);

  if (limit.rlim_cur < config_rlimit_nofile) {
    //WARN("Main : Current RLIMIT_NOFILE is %ul, increasing it to %ul", (unsigned int) limit.rlim_cur, (unsigned int)config_rlimit_nofile);

    if (config_rlimit_nofile > limit.rlim_max) {
      FATAL("The OS doesn't support our requested RLIMIT_NOFILE value");
    }

    limit.rlim_cur = config_rlimit_nofile;

    ret = setrlimit(RLIMIT_NOFILE, &limit);
    FATAL_SYSCALL_ON(ret < 0);
  }
}

static void config_print_version(FILE *stream, int exit_code)
{
  fprintf(stream, "%s\n", PROJECT_VER);
  exit(exit_code);
}

static void config_print_help(FILE *stream, int exit_code)
{
  fprintf(stream, "Start CPC daemon\n");
  fprintf(stream, "\n");
  fprintf(stream, "Usage:\n");
  fprintf(stream, "  cpcd -h/--help : prints this message\n");
  fprintf(stream, "  cpcd -c/--conf file : manually specify the config file\n");
  fprintf(stream, "  cpcd -v/--version : get the version of the daemon\n");
  exit(exit_code);
}
