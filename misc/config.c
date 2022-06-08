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

const char *  config_traces_folder = "/dev/shm/cpcd-traces"; /* must be mounted on a tmpfs */
bool          config_enable_frame_trace = false;

bool          config_use_noop_keep_alive = false;
bool          config_use_encryption = false;

bus_t         config_bus = UNCHOSEN;

// UART config
unsigned int  config_uart_baudrate = 115200;
bool          config_uart_hardflow = false;
const char*   config_uart_file = NULL;

// Board controller
const char*   config_board_controller_ip_addr = NULL;
bool          config_board_controller = false;

//SPI config
const char*   config_spi_file = NULL;
unsigned int  config_spi_bitrate = 1000000;
unsigned int  config_spi_mode = SPI_MODE_0;
unsigned int  config_spi_bit_per_word = 8;
unsigned int  config_spi_cs_pin = 24;
unsigned int  config_spi_irq_pin = 23;

bool          config_recovery_enabled = false;
unsigned int  config_wake_pin = 25;
unsigned int  config_reset_pin = 0;
bool          config_connect_to_bootloader = false;
bool          config_enter_bootloader = false;

const char* const  config_socket_folder = DEFAULT_SOCKET_FOLDER;

const char*   config_instance_name = DEFAULT_INSTANCE_NAME;

bool          config_reset_sequence = true;

operation_mode_t config_operation_mode = MODE_NORMAL;

const char*   config_fu_file = NULL;

const char*   config_binding_key_file = NULL;

const char*   config_binding_method = NULL;

const char*   config_uart_validation_test_option = NULL;

long config_stats_interval = 0;

/*******************************************************************************
 **********************  LOCAL CONFIGURATION VALUES   **************************
 ******************************************************************************/

static const char* config_file_path = DEFAULT_CONFIG_FILE_PATH;

/* New number of concurrent opened file descriptor */
static rlim_t config_rlimit_nofile = 2000;

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
    { "print-stats", required_argument, 0, 's' },
    { "help", no_argument, 0, 'h' },
    { "version", no_argument, 0, 'v' },
    { "bind", required_argument, 0, 'b' },
    { "unbind", no_argument, 0, 'u' },
    { "key", required_argument, 0, 'k' },
    { "firmware-update", required_argument, 0, 'f' },
    { "uart-validation", required_argument, 0, 't' },
    { "board-controller", required_argument, 0, 'w' },
    { "enter-bootloader", no_argument, 0, 'e' },
    { "connect-to-bootloader", no_argument, 0, 'l' },
    { 0, 0, 0, 0  }
  };

  int opt;

  while (1) {
    opt = getopt_long(argc, argv, "c:huvs:f:k:b:t:w:el", opt_list, NULL);

    if (opt == -1) {
      break;
    }

    switch (opt) {
      case 0:
        break;
      case 'c':
        config_file_path = optarg;
        break;
      case 's':
        config_stats_interval = strtol(optarg, NULL, 0);
        FATAL_ON(config_stats_interval <= 0);
        break;
      case 'h':
        config_print_help(stdout, 0);
        break;
      case 'v':
        config_print_version(stdout, 0);
        break;
      case 'b':
        if (config_operation_mode == MODE_NORMAL) {
          config_operation_mode = MODE_BINDING_UNKNOWN;
        } else {
          FATAL("Multiple non normal mode flag detected.");
        }

        if (optarg == NULL) {
          FATAL("Binding method was not provided");
        } else {
          if (0 == strcmp(optarg, "ecdh")) {
            config_operation_mode = MODE_BINDING_ECDH;
          } else if (0 == strcmp(optarg, "plain-text")) {
            config_operation_mode = MODE_BINDING_PLAIN_TEXT;
          } else {
            FATAL("Invalid binding mode");
          }
        }
        break;
      case 'u':
        if (config_operation_mode == MODE_NORMAL) {
          config_operation_mode = MODE_BINDING_UNBIND;
        } else {
          FATAL("Multiple non normal mode flag detected.");
        }
        break;
      case 'k':
        config_binding_key_file = optarg;
        FATAL_ON(config_binding_key_file == NULL);
        break;
      case 'f':
        config_fu_file = optarg;
        if (config_operation_mode == MODE_NORMAL) {
          config_operation_mode = MODE_FIRMWARE_UPDATE;
        } else {
          FATAL("Multiple non normal mode flag detected.");
        }
        break;
      case 't':
        config_uart_validation_test_option = optarg;
        if (config_operation_mode == MODE_NORMAL) {
          config_operation_mode = MODE_UART_VALIDATION;
        } else {
          FATAL("Multiple non normal mode flag detected.");
        }
        break;
      case 'w':
        config_board_controller_ip_addr = optarg;
        config_board_controller = true;
        break;
      case 'l':
        config_connect_to_bootloader = true;
        break;
      case 'e':
        config_enter_bootloader = true;
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
  char match[256] = { 0 };

  // match empty lines
  if ((line[0] == '\n')
      || (line[0] == '\r')) {
    return true;
  }

  // match lines beginning with #, ignoring leading whitespace
  if (sscanf(line, " #%256c", match) == 1) {
    return true;
  }

  // match whitespace-only lines
  if (sscanf(line, "%s", match) == EOF) {
    return true;
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

  PRINT_INFO("path: %s", config_file_path);

  /* Iterate through every line of the file*/
  while (fgets(line, sizeof(line), config_file) != NULL) {
    if (is_comment_or_newline(line)) {
      continue;
    }

    /* Extract name=value pair */
    if (sscanf(line, "%127[^: ]: %127[^\r\n #]%*c", name, val) != 2) {
      FATAL("Config file line \"%s\" doesn't respect syntax. Expecting YAML format (key: value). Please refer to the provided cpcd.conf", line);
    }

    PRINT_INFO("%s: %s", name, val);

    if (0 == strcmp(name, "instance_name")) {
      config_instance_name = strdup(val);
      FATAL_ON(config_instance_name == NULL);
    } else if (0 == strcmp(name, "bus_type")) {
      if (0 == strcmp(val, "UART")) {
        config_bus = UART;
      } else if (0 == strcmp(val, "SPI")) {
        config_bus = SPI;
      } else {
        FATAL("Config file error : bad bus_type value\n");
      }
    } else if (0 == strcmp(name, "spi_device_file")) {
      config_spi_file = strdup(val);
      FATAL_ON(config_spi_file == NULL);
    } else if (0 == strcmp(name, "spi_cs_gpio")) {
      config_spi_cs_pin = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "spi_rx_irq_gpio")) {
      config_spi_irq_pin = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "spi_device_bitrate")) {
      config_spi_bitrate = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "spi_device_mode")) {
      if (0 == strcmp(val, "SPI_MODE_0")) {
        config_spi_mode = SPI_MODE_0;
      } else if (0 == strcmp(val, "SPI_MODE_1")) {
        config_spi_mode = SPI_MODE_1;
      } else if (0 == strcmp(val, "SPI_MODE_2")) {
        config_spi_mode = SPI_MODE_2;
      } else if (0 == strcmp(val, "SPI_MODE_3")) {
        config_spi_mode = SPI_MODE_3;
      } else {
        FATAL("Bad value for spi_device_mode");
      }
    } else if (0 == strcmp(name, "bootloader_recovery_pins_enabled")) {
      if (0 == strcmp(val, "true")) {
        config_recovery_enabled = true;
      } else if (0 == strcmp(val, "false")) {
        config_recovery_enabled = false;
      } else {
        FATAL("Config file error : bad bootloader_recovery_pins_enabled value");
      }
    } else if (0 == strcmp(name, "bootloader_wake_gpio")) {
      config_wake_pin = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "bootloader_reset_gpio")) {
      config_reset_pin = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "uart_device_file")) {
      config_uart_file = strdup(val);
      FATAL_ON(config_uart_file == NULL);
    } else if (0 == strcmp(name, "uart_device_baud")) {
      config_uart_baudrate = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "uart_hardflow")) {
      if (0 == strcmp(val, "true")) {
        config_uart_hardflow = true;
      } else if (0 == strcmp(val, "false")) {
        config_uart_hardflow = false;
      } else {
        FATAL("Config file error : bad UART_HARDFLOW value");
      }
    } else if (0 == strcmp(name, "noop_keep_alive")) {
      if (0 == strcmp(val, "true")) {
        config_use_noop_keep_alive = true;
      } else if (0 == strcmp(val, "false")) {
        config_use_noop_keep_alive = false;
      } else {
        FATAL("Config file error : bad noop_keep_alive value");
      }
    } else if (0 == strcmp(name, "stdout_trace")) {
      if (0 == strcmp(val, "true")) {
        config_stdout_tracing = true;
      } else if (0 == strcmp(val, "false")) {
        config_stdout_tracing = false;
      } else {
        FATAL("Config file error : bad stdout_trace value");
      }
    } else if (0 == strcmp(name, "trace_to_file")) {
      if (0 == strcmp(val, "true")) {
        tmp_config_file_tracing = true;
      } else if (0 == strcmp(val, "false")) {
        tmp_config_file_tracing = false;
      } else {
        FATAL("Config file error : bad trace_to_file value");
      }
    } else if (0 == strcmp(name, "enable_frame_trace")) {
      if (0 == strcmp(val, "true")) {
        config_enable_frame_trace = true;
      } else if (0 == strcmp(val, "false")) {
        config_enable_frame_trace = false;
      } else {
        FATAL("Config file error : bad enable_frame_trace value");
      }
    } else if (0 == strcmp(name, "disable_encryption")) {
      if (0 == strcmp(val, "true")) {
        config_use_encryption = false;
      } else if (0 == strcmp(val, "false")) {
        config_use_encryption = true;
      } else {
        FATAL("Config file error : bad disable_encryption value");
      }
    } else if (0 == strcmp(name, "reset_sequence")) {
      if (0 == strcmp(val, "true")) {
        config_reset_sequence = true;
      } else if (0 == strcmp(val, "false")) {
        config_reset_sequence = false;
      } else {
        FATAL("Config file error : bad reset_sequence value");
      }
    } else if (0 == strcmp(name, "traces_folder")) {
      config_traces_folder = strdup(val);
      FATAL_ON(config_traces_folder == NULL);
    } else if (0 == strcmp(name, "rlimit_nofile")) {
      config_rlimit_nofile = strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Config file error : bad rlimit_nofile value");
      }
    } else if (0 == strcmp(name, "enable_lttng_tracing")) {
#ifdef COMPILE_LTTNG
      if (0 == strcmp(val, "true")) {
        config_lttng_tracing = true;
      } else if (0 == strcmp(val, "false")) {
        config_reset_sequence = false;
      } else {
        fprintf(stderr, "Config file error : bad enable_lttng_tracing value\n");
      }
#else
      if (0 == strcmp(val, "true")) {
        fprintf(stderr, "Config file error : lttng support is not compiled with this executable\n");
      } else if (0 == strcmp(val, "false")) {
        config_reset_sequence = false;
      } else {
        fprintf(stderr, "Config file error : bad enable_lttng_tracing value\n");
      }
#endif
    } else if (0 == strcmp(name, "binding_key_file")) {
      if (config_binding_key_file == NULL) {
        config_binding_key_file = strdup(val);
        FATAL_ON(config_binding_key_file == NULL);
      }
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
  int ret;

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
      FATAL("Firmware update file %s is not accessible.", config_fu_file);
    }
    /* TODO : Test for proper file extension and/or whether it is a valid image file for the bootloader */
  }

  if (config_use_encryption && config_operation_mode != MODE_BINDING_UNBIND) {
    if (config_binding_key_file == NULL) {
      FATAL("No binding key file provided needed for security. Provide BINDING_KEY_FILE in the configuration file or use the --key argument. ");
    }

    // ECDH Mode binding writes the key
    if (config_operation_mode != MODE_BINDING_ECDH) {
      if (access(config_binding_key_file, F_OK | R_OK) != 0) {
        FATAL("Cannot access binding key file with read permissions \'%s\'.", config_binding_key_file);
      }
    }
  }

  if (config_operation_mode == MODE_BINDING_ECDH) {
    if (access(config_binding_key_file, F_OK) == 0 ) {
      FATAL("Binding key file already exist at provided location. Cannot overwrite it.\'%s\'.", config_binding_key_file);
    }

    // Create empty file to validate write permissions at provided path
    FILE *binding_key_file = fopen(config_binding_key_file, "w");
    if (binding_key_file == NULL) {
      FATAL("Failed to write keyfile at provided location (%s) errno: %m", config_binding_key_file);
    }
    FATAL_SYSCALL_ON(binding_key_file == NULL);
    ret = fclose(binding_key_file);
    FATAL_SYSCALL_ON(ret != 0);
  }

  if (config_connect_to_bootloader && config_operation_mode != MODE_FIRMWARE_UPDATE) {
    FATAL("Bootloader connect only supported for firmware updates.");
  }

  if (config_connect_to_bootloader && config_enter_bootloader) {
    FATAL("Cannot select both --enter-bootloader and --connect-to-bootloader");
  }

  if (config_enter_bootloader) {
    config_operation_mode = MODE_FIRMWARE_UPDATE;
  }

  if (config_file_tracing) {
    init_file_logging();
  }

  if (config_stats_interval > 0) {
    init_stats_logging();
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
  fprintf(stream, "  cpcd -c/--conf <file> : manually specify the config file\n");
  fprintf(stream, "  cpcd -v/--version : get the version of the daemon\n");
  fprintf(stream, "  cpcd -f/--firmware-update <file> : Specify the .gbl file to update the secondary's firmware with\n");
  fprintf(stream, "  cpcd -b/--bind <method> : bind to the secondary using the provided key in the config file or the --key argument. Currently supported methods: ecdh or plain-text\n");
  fprintf(stream, "  cpcd -u/--unbind : attempt to unbind from the secondary.\n");
  fprintf(stream, "  cpcd -k/--key <file> : provide the binding keyfile to read from or write to, this argument will override the BINDING_KEY_FILE config\n");
  fprintf(stream, "  cpcd -s/--print-stats <interval> : print debug statistics to traces. Must provide a given interval in seconds\n");
  fprintf(stream, "  cpcd -w/--wireless-kit-ip <ipaddress> : validates board controller vcom configuration.\n");
  fprintf(stream, "  cpcd -t/--uart-validation <test> : provide test option to run: 1 -> RX/TX, 2 -> RTS/CTS\n");
  fprintf(stream, "  cpcd -e/--enter-bootloader : restart the secondary device in bootloader and exit.\n");
  fprintf(stream, "  cpcd -l/--connect-to-bootloader : connect directly to bootloader. Only supported with firmware update.\n");
  exit(exit_code);
}
