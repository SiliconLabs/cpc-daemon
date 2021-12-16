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

#include <sys/resource.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/spi/spidev.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>

#include "config.h"
#include "logging.h"
#include "version.h"

/*******************************************************************************
 **********************  GLOBAL CONFIGURATION VALUES   *************************
 ******************************************************************************/
int           config_stdout_tracing = 0;
int           config_file_tracing = 1; /* Set to true to have the chance to catch early traces.
                                          It will be set to false after config file parsing. */
int           config_lttng_tracing = 0;

const char *  config_traces_folder = "./cpcd-traces";

bool          config_use_noop_keep_alive = false;
bool          config_use_encryption = false;

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
unsigned int  config_spi_wake_pin = 25;

const char* const  config_socket_folder = DEFAULT_SOCKET_FOLDER;

const char*   config_instance_name = DEFAULT_INSTANCE_NAME;

bool          config_reset_sequence = true;

operation_mode_t config_operation_mode = MODE_NORMAL;

const char*   config_fu_file = NULL;

const char*   config_binding_key_file = NULL;

/*******************************************************************************
 **********************  LOCAL CONFIGURATION VALUES   **************************
 ******************************************************************************/

static const char* config_file_path = DEFAULT_CONFIG_FILE_PATH;

/* New number of concurrent opened file descriptor */
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
    { "bind", no_argument, 0, 'b' },
    { "firmware-update", required_argument, 0, 'f' },
    { 0, 0, 0, 0  }
  };

  int opt;

  while (1) {
    opt = getopt_long(argc, argv, "c:bhvf:", opt_list, NULL);

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
      case 'b':
        if (config_operation_mode == MODE_NORMAL) {
          config_operation_mode = MODE_BINDING_PLAIN_TEXT;
        } else {
          FATAL("Multiple non normal mode flag detected.");
        }
        break;
      case 'f':
        config_fu_file = optarg;
        if (config_operation_mode == MODE_NORMAL) {
          config_operation_mode = MODE_FIRMWARE_UPDATE;
        } else {
          FATAL("Multiple non normal mode flag detected.");
        }
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

  if ((line[0] == '\n')
      || (line[0] == '\r')) {
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

static void config_parse_config_file(void)
{
  FILE *config_file = NULL;
  char name[128] = { 0 };
  char val[128] = { 0 };
  char line[256] = { 0 };
  char *endptr = NULL;
  int tmp_config_file_tracing = 0;

  config_file = fopen(config_file_path, "r");

  if (config_file == NULL) {
    FATAL("Could not open the configuration file under: %s, please install the configuration file there or provide a valid path with --conf\n", config_file_path);
  }

  /* Iterate through every line of the file*/
  while (fgets(line, sizeof(line), config_file) != NULL) {
    if (is_comment_or_newline(line)) {
      continue;
    }

    /* Extract name=value pair */
    if (sscanf(line, "%127[^=]=%127[^\r\n]%*c", name, val) != 2) {
      FATAL("Config file line \"%s\" doesn't respect syntax", line);
    }

    if (0 == strcmp(name, "INSTANCE_NAME")) {
      config_instance_name = strdup(val);
      FATAL_ON(config_instance_name == NULL);
    } else if (0 == strcmp(name, "BUS_TYPE")) {
      if (0 == strcmp(val, "UART")) {
        config_bus = UART;
      } else if (0 == strcmp(val, "SPI")) {
        config_bus = SPI;
      } else {
        FATAL("Config file error : bad BUS_TYPE value\n");
      }
    } else if (0 == strcmp(name, "SPI_DEVICE_FILE")) {
      config_spi_file = strdup(val);
      FATAL_ON(config_spi_file == NULL);
    } else if (0 == strcmp(name, "SPI_CS_GPIO")) {
      config_spi_cs_pin = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "SPI_RX_IRQ_GPIO")) {
      config_spi_irq_pin = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "SPI_DEVICE_BITRATE")) {
      config_spi_bitrate = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "SPI_DEVICE_MODE")) {
      if (0 == strcmp(val, "SPI_MODE_0")) {
        config_spi_mode = SPI_MODE_0;
      } else if (0 == strcmp(val, "SPI_MODE_1")) {
        config_spi_mode = SPI_MODE_1;
      } else if (0 == strcmp(val, "SPI_MODE_2")) {
        config_spi_mode = SPI_MODE_2;
      } else if (0 == strcmp(val, "SPI_MODE_3")) {
        config_spi_mode = SPI_MODE_3;
      } else {
        FATAL("Bad value for SPI_DEVICE_MODE");
      }
    } else if (0 == strcmp(name, "SPI_WAKE_GPIO")) {
      config_spi_wake_pin = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "UART_DEVICE_FILE")) {
      config_uart_file = strdup(val);
      FATAL_ON(config_uart_file == NULL);
    } else if (0 == strcmp(name, "UART_DEVICE_BAUD")) {
      config_uart_baudrate = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "UART_HARDFLOW")) {
      if (0 == strcmp(val, "true")) {
        config_uart_hardflow = true;
      } else if (0 == strcmp(val, "false")) {
        config_uart_hardflow = false;
      } else {
        FATAL("Config file error : bad UART_HARDFLOW value");
      }
    } else if (0 == strcmp(name, "NOOP_KEEP_ALIVE")) {
      if (0 == strcmp(val, "true")) {
        config_use_noop_keep_alive = true;
      } else if (0 == strcmp(val, "false")) {
        config_use_noop_keep_alive = false;
      } else {
        FATAL("Config file error : bad NOOP_KEEP_ALIVE value");
      }
    } else if (0 == strcmp(name, "STDOUT_TRACE")) {
      if (0 == strcmp(val, "true")) {
        config_stdout_tracing = true;
      } else if (0 == strcmp(val, "false")) {
        config_stdout_tracing = false;
      } else {
        FATAL("Config file error : bad STDOUT_TRACE value");
      }
    } else if (0 == strcmp(name, "TRACE_TO_FILE")) {
      if (0 == strcmp(val, "true")) {
        tmp_config_file_tracing = true;
      } else if (0 == strcmp(val, "false")) {
        tmp_config_file_tracing = false;
      } else {
        FATAL("Config file error : bad TRACE_TO_FILE value");
      }
    } else if (0 == strcmp(name, "DISABLE_ENCRYPTION")) {
      if (0 == strcmp(val, "true")) {
        config_use_encryption = false;
      } else if (0 == strcmp(val, "false")) {
        config_use_encryption = true;
      } else {
        FATAL("Config file error : bad DISABLE_ENCRYPTION value");
      }
    } else if (0 == strcmp(name, "RESET_SEQUENCE")) {
      if (0 == strcmp(val, "true")) {
        config_reset_sequence = true;
      } else if (0 == strcmp(val, "false")) {
        config_reset_sequence = false;
      } else {
        FATAL("Config file error : bad RESET_SEQUENCE value");
      }
    } else if (0 == strcmp(name, "TRACES_FOLDER")) {
      config_traces_folder = strdup(val);
      FATAL_ON(config_traces_folder == NULL);
    } else if (0 == strcmp(name, "RLIMIT_NOFILE")) {
      config_rlimit_nofile = strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Config file error : bad RLIMIT_NOFILE value");
      }
    } else if (0 == strcmp(name, "ENABLE_LTTNG_TRACING")) {
#ifdef COMPILE_LTTNG
      if (0 == strcmp(val, "true")) {
        config_lttng_tracing = true;
      } else if (0 == strcmp(val, "false")) {
        config_reset_sequence = false;
      } else {
        fprintf(stderr, "Config file error : bad ENABLE_LTTNG_TRACING value\n");
      }
#else
      if (0 == strcmp(val, "true")) {
        fprintf(stderr, "Config file error : lttng support is not compiled with this executable\n");
      } else if (0 == strcmp(val, "false")) {
        config_reset_sequence = false;
      } else {
        fprintf(stderr, "Config file error : bad ENABLE_LTTNG_TRACING value\n");
      }
#endif
    } else if (0 == strcmp(name, "BINDING_KEY_FILE")) {
      config_binding_key_file = strdup(val);
      FATAL_ON(config_binding_key_file == NULL);
    } else {
      FATAL("Config file error : key \"%s\" not recognized", name);
    }
  }

  config_file_tracing = tmp_config_file_tracing;

  fclose(config_file);
}

/*
 * Running two instances of the daemon over the same hardware device must be prohibited.
 * In order to detect when a daemon is bound to a device, file locks are used.
 */
static void prevent_device_collision(const char* const device_name)
{
  int tmp_fd = open(device_name, O_RDWR | O_CLOEXEC);

  /* Try to apply a cooperative exclusive file lock on the device file. Don't block */
  int ret = flock(tmp_fd, LOCK_EX | LOCK_NB);

  if (ret == 0) {
    /* The device file is free to use, leave this file descriptor open
     * to preserve the lock. */
  } else if (errno == EWOULDBLOCK) {
    FATAL("The device \"%s\" is locked by another cpcd instance", device_name);
  } else {
    FATAL_SYSCALL_ON(0);
  }
}

/*
 * Running two instances of the daemon with the same instance name must be prohibited.
 * A file lock over the control socket is used to detect when an instance is running.
 */
static void prevent_instance_collision(const char* const instance_name)
{
  struct sockaddr_un name;
  int ctrl_sock_fd;

  /* Create datagram socket for control */
  ctrl_sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  FATAL_SYSCALL_ON(ctrl_sock_fd < 0);

  /* Clear struct for portability */
  memset(&name, 0, sizeof(name));

  name.sun_family = AF_UNIX;

  /* Create the control socket path */
  {
    int nchars;
    const size_t size = sizeof(name.sun_path) - sizeof('\0');

    nchars = snprintf(name.sun_path, size, "%s/cpcd/%s/ctrl.cpcd.sock", config_socket_folder, instance_name);

    /* Make sure the path fitted entirely */
    FATAL_ON(nchars < 0 || (size_t) nchars >= size);
  }

  /* Try to connect to the socket in order to see if we collide with another daemon */
  {
    int ret;

    ret = connect(ctrl_sock_fd, (const struct sockaddr *) &name, sizeof(name));

    (void) close(ctrl_sock_fd);

    if (ret == 0) {
      FATAL("Another daemon instance is already running with the same instance name : %s.", name.sun_path);
    } else {
      /* good to go */
    }
  }
}

static void config_validate_configuration(void)
{
  /* Validate bus configuration */
  {
    if (config_bus == SPI) {
      if (config_spi_file == NULL) {
        FATAL("SPI device file missing");
      }

      prevent_device_collision(config_spi_file);
    } else if (config_bus == UART) {
      if (config_uart_file == NULL) {
        FATAL("UART device file missing");
      }

      prevent_device_collision(config_uart_file);
    } else {
      FATAL("Invalid bus configuration.");
    }
  }

  prevent_instance_collision(config_instance_name);

  if (config_operation_mode == MODE_FIRMWARE_UPDATE) {
    if ( access(config_fu_file, F_OK | R_OK) != 0 ) {
      FATAL("Firmware update file is not accessible.");
    }
    /* TODO : Test for proper file extension and/or whether it is a valid image file for the bootloader */
  }

  if ((config_operation_mode == MODE_NORMAL && config_use_encryption)
      || config_operation_mode == MODE_BINDING_PLAIN_TEXT ) {
    if (config_binding_key_file == NULL) {
      FATAL("No binding key file provided needed for security. Provide BINDING_KEY_FILE in the configuration file. ");
    } else if ( access(config_binding_key_file, F_OK | R_OK) != 0) {
      FATAL("Cannot access binding key file \'%s\'.", config_binding_key_file);
    }
  }

  if (config_file_tracing) {
    init_file_logging();
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
#ifndef GIT_SHA1
#define GIT_SHA1 "missing SHA1"
#endif

#ifndef GIT_REFSPEC
#define GIT_REFSPEC "missing refspec"
#endif

  fprintf(stream, "%s\n", PROJECT_VER);
  fprintf(stream, "GIT commit: %s\n", GIT_SHA1);
  fprintf(stream, "GIT branch: %s\n", GIT_REFSPEC);
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
  fprintf(stream, "  cpcd -f/--firmware-update : Specify the .gbl file to update the secondary's firmware with\n");
  fprintf(stream, "  cpcd -b/--bind: bind to the secondary using the provided key in the config file\n");
  exit(exit_code);
}
