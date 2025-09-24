/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Config Interface
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

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

#include "cpcd/config.h"
#include "cpcd/logging.h"
#include "cpcd/sleep.h"
#include "cpcd/utils.h"

#ifndef DEFAULT_INSTANCE_NAME
  #define DEFAULT_INSTANCE_NAME "cpcd_0"
#endif

/*******************************************************************************
 **********************  DATA TYPES   ******************************************
 ******************************************************************************/
typedef struct {
  char *val;
  char *name;
  bool has_arg;
} argv_exclude_t;

/*******************************************************************************
 **********************  GLOBAL CONFIGURATION VALUES   *************************
 ******************************************************************************/
config_t config = {
  .file_path = CPCD_CONFIG_FILE_PATH,

  .instance_name = DEFAULT_INSTANCE_NAME,

  .socket_folder = CPC_SOCKET_DIR,

  .operation_mode = MODE_NORMAL,

  .use_encryption = false,

  .binding_key_file = "~/.cpcd/binding.key",

  .binding_key_override = false,

  .binding_method = NULL,

  .stdout_tracing = false,
  .file_tracing = true, // Set to true to have the chance to catch early traces. It will be set to false after config file parsing.
  .lttng_tracing = false,
  .enable_frame_trace = false,
  .traces_folder = "/dev/shm/cpcd-traces", // must be mounted on a tmpfs

  .bus = UNCHOSEN,

  // UART config
  .uart_baudrate = 115200,
  .uart_hardflow = false,
  .uart_file = NULL,

  // SPI config
  .spi_file = NULL,
  .spi_bitrate = 1000000,
  .spi_irq_chip = NULL,
  .spi_irq_pin = 0,

  // Firmware update
  .fwu_reset_chip = NULL,
  .fwu_spi_reset_pin = -1,
  .fwu_wake_chip = NULL,
  .fwu_spi_wake_pin = -1,
  .fwu_recovery_pins_enabled = false,
  .fwu_connect_to_bootloader = false,
  .fwu_enter_bootloader = false,
  .fwu_file = NULL,

  .restart_cpcd = false,

  .board_controller_ip_addr = NULL,

  .application_version_validation = NULL,

  .print_secondary_versions_and_exit = false,

  .use_noop_keep_alive = false,

  .reset_sequence = true,

  .uart_validation_test_option = NULL,

  .stats_interval = 0,

  .rlimit_nofile = 2000, // New number of concurrent opened file descriptor
};

/*******************************************************************************
 **************************  LOCAL PROTOTYPES   ********************************
 ******************************************************************************/

static void config_print_version(FILE *stream, int exit_code);

static void config_print_help(FILE *stream, int exit_code);

static void config_parse_cli_arg(int argc, char *argv[]);

static void config_set_rlimit_nofile(void);

static void config_validate_configuration(void);

static void config_parse_config_file(void);

static void config_expand_binding_key_location(void);

static void config_parse_multicast_endpoints(const char *input);

/*******************************************************************************
 ****************************  IMPLEMENTATION   ********************************
 ******************************************************************************/
static const char* config_bool_to_str(bool value)
{
  return value ? "true" : "false";
}

static const char* config_to_str(const char *value)
{
  return value ? value : "";
}

static const char* config_bus_to_str(bus_t value)
{
  switch (value) {
    case UART:
      return "UART";
    case SPI:
      return "SPI";
    case NETLINK_SDIO:
      return "NETLINK_SDIO";
#if defined(ENABLE_SOCKET_DRIVER)
    case SOCKET:
      return "SOCKET";
#endif
    case UNCHOSEN:
      return "UNCHOSEN";
    default:
      FATAL("bus_t value not supported (%d)", value);
  }
}

static const char* config_operation_mode_to_str(operation_mode_t value)
{
  switch (value) {
    case MODE_NORMAL:
      return "MODE_NORMAL";
    case MODE_BINDING_UNKNOWN:
      return "MODE_BINDING_UNKNOWN";
    case MODE_BINDING_ECDH:
      return "MODE_BINDING_ECDH";
    case MODE_BINDING_PLAIN_TEXT:
      return "MODE_BINDING_PLAIN_TEXT";
    case MODE_BINDING_UNBIND:
      return "MODE_BINDING_UNBIND";
    case MODE_FIRMWARE_UPDATE:
      return "MODE_FIRMWARE_UPDATE";
    case MODE_UART_VALIDATION:
      return "MODE_UART_VALIDATION";
    default:
      FATAL("operation_mode_t value not supported (%d)", value);
  }
}

#define CONFIG_PREFIX_LEN(variable) (strlen(#variable) + 1)

#define CONFIG_PRINT_SILENCE(value)                 \
  do {                                              \
    run_time_total_size += (uint32_t)sizeof(value); \
  } while (0)

#define CONFIG_PRINT_STR_COND(value, cond)                                    \
  do {                                                                        \
    if (cond && value) {                                                      \
      PRINT_INFO("  %s = %s", &(#value)[print_offset], config_to_str(value)); \
    }                                                                         \
    run_time_total_size += (uint32_t)sizeof(value);                           \
  } while (0)

#define CONFIG_PRINT_STR(value) CONFIG_PRINT_STR_COND(value, true)

#define CONFIG_PRINT_BOOL_TO_STR_COND(value, cond)                                 \
  do {                                                                             \
    if (cond) {                                                                    \
      PRINT_INFO("  %s = %s", &(#value)[print_offset], config_bool_to_str(value)); \
    }                                                                              \
    run_time_total_size += (uint32_t)sizeof(value);                                \
  } while (0)

#define CONFIG_PRINT_BOOL_TO_STR(value) CONFIG_PRINT_BOOL_TO_STR_COND(value, true)

#define CONFIG_PRINT_OPERATION_MODE_TO_STR(value)                                          \
  do {                                                                                     \
    PRINT_INFO("  %s = %s", &(#value)[print_offset], config_operation_mode_to_str(value)); \
    run_time_total_size += (uint32_t)sizeof(value);                                        \
  } while (0)

#define CONFIG_PRINT_BUS_TO_STR(value)                                          \
  do {                                                                          \
    PRINT_INFO("  %s = %s", &(#value)[print_offset], config_bus_to_str(value)); \
    run_time_total_size += (uint32_t)sizeof(value);                             \
  } while (0)

#define CONFIG_PRINT_DEC_COND(value, cond)                     \
  do {                                                         \
    if (cond) {                                                \
      PRINT_INFO("  %s = %d", &(#value)[print_offset], value); \
    }                                                          \
    run_time_total_size += (uint32_t)sizeof(value);            \
  } while (0)

#define CONFIG_PRINT_DEC(value) CONFIG_PRINT_DEC_COND(value, true)

#define CONFIG_PRINT_MULTICAST_ENDPOINTS(value)                                         \
  do {                                                                                  \
    char __buf[2048] = { 0 };                                                           \
    char *__ptr = __buf;                                                                \
    bool __first = true;                                                                \
    __ptr += sprintf(__ptr, "[");                                                       \
    int __start_range = -1;                                                             \
    for (int i = 0; i < SL_CPC_ENDPOINT_MAX_COUNT; i++) {                               \
      if ((value)[i]) {                                                                 \
        if (__start_range == -1) {                                                      \
          __start_range = i;                                                            \
        }                                                                               \
      } else {                                                                          \
        if (__start_range != -1) {                                                      \
          if (!__first) {                                                               \
            __ptr += sprintf(__ptr, ", ");                                              \
          }                                                                             \
          if (__start_range == i - 1) {                                                 \
            __ptr += sprintf(__ptr, "%d", __start_range);                               \
          } else {                                                                      \
            __ptr += sprintf(__ptr, "%d-%d", __start_range, i - 1);                     \
          }                                                                             \
          __first = false;                                                              \
          __start_range = -1;                                                           \
        }                                                                               \
      }                                                                                 \
    }                                                                                   \
    if (__start_range != -1) {                                                          \
      if (!__first) {                                                                   \
        __ptr += sprintf(__ptr, ", ");                                                  \
      }                                                                                 \
      if (__start_range == SL_CPC_ENDPOINT_MAX_COUNT - 1) {                             \
        __ptr += sprintf(__ptr, "%d", __start_range);                                   \
      } else {                                                                          \
        __ptr += sprintf(__ptr, "%d-%d", __start_range, SL_CPC_ENDPOINT_MAX_COUNT - 1); \
      }                                                                                 \
    }                                                                                   \
    sprintf(__ptr, "]");                                                                \
    PRINT_INFO("  %s = %s", &(#value)[print_offset], __buf);                            \
    run_time_total_size += (uint32_t)sizeof(value);                                     \
  } while (0)

static void config_print(void)
{
  PRINT_INFO("Reading configuration");

  size_t print_offset = CONFIG_PREFIX_LEN(config);

  uint32_t compile_time_total_size = (uint32_t)sizeof(config_t);
  uint32_t run_time_total_size = 0;

  CONFIG_PRINT_STR(config.file_path);

  CONFIG_PRINT_STR(config.instance_name);

  CONFIG_PRINT_STR(config.socket_folder);

  CONFIG_PRINT_OPERATION_MODE_TO_STR(config.operation_mode);

  CONFIG_PRINT_BOOL_TO_STR(config.use_encryption);

  CONFIG_PRINT_STR(config.binding_key_file);
  CONFIG_PRINT_SILENCE(config.binding_key_override); // used only for internal logic

  CONFIG_PRINT_STR(config.binding_method);

  CONFIG_PRINT_BOOL_TO_STR(config.stdout_tracing);
  CONFIG_PRINT_BOOL_TO_STR(config.file_tracing);
  CONFIG_PRINT_BOOL_TO_STR(config.lttng_tracing);
  CONFIG_PRINT_BOOL_TO_STR(config.enable_frame_trace);
  CONFIG_PRINT_STR(config.traces_folder);

  CONFIG_PRINT_BUS_TO_STR(config.bus);

  CONFIG_PRINT_DEC_COND(config.uart_baudrate, config.bus == UART);
  CONFIG_PRINT_BOOL_TO_STR_COND(config.uart_hardflow, config.bus == UART);
  CONFIG_PRINT_STR_COND(config.uart_file, config.bus == UART);

  CONFIG_PRINT_STR_COND(config.spi_file, config.bus == SPI);
  CONFIG_PRINT_DEC_COND(config.spi_bitrate, config.bus == SPI);
  CONFIG_PRINT_STR_COND(config.spi_irq_chip, config.bus == SPI);
  CONFIG_PRINT_DEC_COND(config.spi_irq_pin, config.bus == SPI);

  CONFIG_PRINT_BOOL_TO_STR(config.fwu_recovery_pins_enabled);
  CONFIG_PRINT_STR_COND(config.fwu_reset_chip, config.fwu_recovery_pins_enabled);
  CONFIG_PRINT_DEC_COND(config.fwu_spi_reset_pin, config.fwu_recovery_pins_enabled);
  CONFIG_PRINT_STR_COND(config.fwu_wake_chip, config.fwu_recovery_pins_enabled);
  CONFIG_PRINT_DEC_COND(config.fwu_spi_wake_pin, config.fwu_recovery_pins_enabled);

  CONFIG_PRINT_BOOL_TO_STR(config.fwu_connect_to_bootloader);
  CONFIG_PRINT_BOOL_TO_STR(config.fwu_enter_bootloader);
  CONFIG_PRINT_STR(config.fwu_file);
  CONFIG_PRINT_BOOL_TO_STR(config.restart_cpcd);

  CONFIG_PRINT_STR(config.board_controller_ip_addr);

  CONFIG_PRINT_BOOL_TO_STR(config.application_version_validation);

  CONFIG_PRINT_BOOL_TO_STR(config.print_secondary_versions_and_exit);

  CONFIG_PRINT_BOOL_TO_STR(config.use_noop_keep_alive);

  CONFIG_PRINT_BOOL_TO_STR(config.reset_sequence);

  CONFIG_PRINT_STR(config.uart_validation_test_option);

  CONFIG_PRINT_DEC(config.stats_interval);

  CONFIG_PRINT_DEC(config.rlimit_nofile);

  CONFIG_PRINT_MULTICAST_ENDPOINTS(config.multicast_endpoints);

  if (run_time_total_size != compile_time_total_size) {
    FATAL("A new config was added to config_t but it was not printed. run_time_total_size (%d) != compile_time_total_size (%d)", run_time_total_size, compile_time_total_size);
  }
}

void config_init(int argc, char *argv[])
{
  config_parse_cli_arg(argc, argv);

  config_parse_config_file();

  config_expand_binding_key_location();

  config_validate_configuration();

  config_set_rlimit_nofile();

  config_print();
}

static void config_expand_binding_key_location(void)
{
  char binding_key_absolute_path[PATH_MAX];
  FATAL_ON(config.binding_key_file == NULL);

  // Look for a tilde
  char *tilde = strchr(config.binding_key_file, '~');

  if (tilde != NULL && tilde != &config.binding_key_file[0]) {
    FATAL("Binding key file path contains a tilde (~) that is not a prefix");
  } else if (tilde == &config.binding_key_file[0]) {
    // Make sure there is something after the tilde
    if (config.binding_key_file[1] == '\0') {
      FATAL("Binding key file path is invalid");
    }

    // Look for another tilde
    char *excess_tilde = strchr(&config.binding_key_file[1], '~');
    if (excess_tilde != NULL) {
      FATAL("Binding key file path contains a tilde (~) that is not a prefix");
    }

    // Expand home directory
    glob_t home_dir;

    int ret = glob("~", GLOB_TILDE, NULL, &home_dir);
    FATAL_SYSCALL_ON(ret != 0);

    strcpy(binding_key_absolute_path, home_dir.gl_pathv[0]);
    strcat(binding_key_absolute_path, &config.binding_key_file[1]);

    config.binding_key_file = strdup(binding_key_absolute_path);

    globfree(&home_dir);
  }
}

static void print_cli_args(int argc, char *argv[])
{
  char *cli_args;
  size_t cli_args_size = 0;

  for (int i = 0; i < argc; i++) {
    if (argv[i]) {
      cli_args_size += strlen(argv[i]) + strlen(" ") + 1;
    }
  }

  cli_args = zalloc(cli_args_size);
  FATAL_SYSCALL_ON(cli_args == NULL);

  for (int i = 0; i < argc; i++) {
    if (argv[i]) {
      strcat(cli_args, argv[i]);
      strcat(cli_args, " ");
    }
  }

  PRINT_INFO("%s", cli_args);
  free(cli_args);
}

#define ARGV_OPT_CONF                   "conf"
#define ARGV_OPT_PRINT_STATS            "print-stats"
#define ARGV_OPT_HELP                   "help"
#define ARGV_OPT_VERSION                "version"
#define ARGV_OPT_SECONDARY_VERSIONS     "secondary-versions"
#define ARGV_OPT_APP_VERSION            "app-version"
#define ARGV_OPT_BIND                   "bind"
#define ARGV_OPT_UNBIND                 "unbind"
#define ARGV_OPT_KEY                    "key"
#define ARGV_OPT_FIRMWARE_UPDATE        "firmware-update"
#define ARGV_OPT_RESTART_CPCD           "restart-cpcd"
#define ARGV_OPT_ENTER_BOOTLOADER       "enter-bootloader"
#define ARGV_OPT_CONNECT_TO_BOOTLOADER  "connect-to-bootloader"
#define ARGV_OPT_UART_VALIDATION        "uart-validation"
#define ARGV_OPT_BOARD_CONTROLLER       "board-controller"

const struct option argv_opt_list[] =
{
  { ARGV_OPT_CONF, required_argument, 0, 'c' },
  { ARGV_OPT_PRINT_STATS, required_argument, 0, 's' },
  { ARGV_OPT_HELP, no_argument, 0, 'h' },
  { ARGV_OPT_VERSION, no_argument, 0, 'v' },
  { ARGV_OPT_SECONDARY_VERSIONS, no_argument, 0, 'p' },
  { ARGV_OPT_BIND, required_argument, 0, 'b' },
  { ARGV_OPT_UNBIND, no_argument, 0, 'u' },
  { ARGV_OPT_KEY, required_argument, 0, 'k' },
  { ARGV_OPT_FIRMWARE_UPDATE, required_argument, 0, 'f' },
  { ARGV_OPT_APP_VERSION, required_argument, 0, 'a' },
  { ARGV_OPT_RESTART_CPCD, no_argument, 0, 'r' },
  { ARGV_OPT_ENTER_BOOTLOADER, no_argument, 0, 'e' },
  { ARGV_OPT_CONNECT_TO_BOOTLOADER, no_argument, 0, 'l' },
  { ARGV_OPT_UART_VALIDATION, required_argument, 0, 't' },
  { ARGV_OPT_BOARD_CONTROLLER, required_argument, 0, 'w' },
  { 0, 0, 0, 0  }
};

static void config_parse_cli_arg(int argc, char *argv[])
{
  int opt;

  PRINT_INFO("Reading cli arguments");

  print_cli_args(argc, argv);

  while (1) {
    opt = getopt_long(argc, argv, "c:hupvrs:f:k:a:b:t:w:el", argv_opt_list, NULL);

    if (opt == -1) {
      if (optind < argc) {
        fprintf(stderr, "Unknown option: %s\n", argv[optind]);
        config_print_help(stderr, 1);
      }
      break;
    }

    switch (opt) {
      case 0:
        break;
      case 'c':
        config.file_path = optarg;
        break;
      case 's':
        config.stats_interval = (int)strtol(optarg, NULL, 0);
        FATAL_ON(config.stats_interval <= 0);
        break;
      case 'h':
        config_print_help(stdout, 0);
        break;
      case 'v':
        config_print_version(stdout, 0);
        break;
      case 'a':
        config.application_version_validation = optarg;
        break;
      case 'p':
        config.print_secondary_versions_and_exit = true;
        break;
      case 'b':
        if (config.operation_mode == MODE_NORMAL) {
          config.operation_mode = MODE_BINDING_UNKNOWN;
        } else {
          FATAL("Multiple non normal mode flag detected.");
        }

        if (optarg == NULL) {
          FATAL("Binding method was not provided");
        } else {
          if (0 == strcmp(optarg, "ecdh")) {
            config.operation_mode = MODE_BINDING_ECDH;
          } else if (0 == strcmp(optarg, "plain-text")) {
            config.operation_mode = MODE_BINDING_PLAIN_TEXT;
          } else {
            FATAL("Invalid binding mode");
          }
        }
        break;
      case 'u':
        if (config.operation_mode == MODE_NORMAL) {
          config.operation_mode = MODE_BINDING_UNBIND;
        } else {
          FATAL("Multiple non normal mode flag detected.");
        }
        break;
      case 'k':
        config.binding_key_override = true;
        config.binding_key_file = strdup(optarg);
        FATAL_ON(config.binding_key_file == NULL);
        break;
      case 'f':
        config.fwu_file = optarg;
        if (config.operation_mode == MODE_NORMAL) {
          config.operation_mode = MODE_FIRMWARE_UPDATE;
        } else {
          FATAL("Multiple non normal mode flag detected.");
        }
        break;
      case 'r':
        config.restart_cpcd = true;
        break;
      case 't':
        config.uart_validation_test_option = optarg;
        if (config.operation_mode == MODE_NORMAL) {
          config.operation_mode = MODE_UART_VALIDATION;
        } else {
          FATAL("Multiple non normal mode flag detected.");
        }
        break;
      case 'w':
        config.board_controller_ip_addr = optarg;
        break;
      case 'l':
        config.fwu_connect_to_bootloader = true;
        break;
      case 'e':
        config.fwu_enter_bootloader = true;
        break;
      case '?':
      default:
        fprintf(stderr, "Unknown option: %s", argv[optind]);
        config_print_help(stderr, 1);
        break;
    }
  }
}

static void config_restart_cpcd_without_args(argv_exclude_t *argv_exclude_list, size_t argc_exclude_list)
{
  size_t exclude_list_size = argc_exclude_list / sizeof(argv_exclude_t);
  size_t option_list_size = sizeof(argv_opt_list) / sizeof(struct option);
  extern char **argv_g;
  extern int argc_g;
  char **argv;

  // Populate argv_exclude_list according to argv_opt_list
  for (size_t i = 0; i < exclude_list_size; i++) {
    for (size_t j = 0; j < option_list_size; j++) {
      if (argv_opt_list[j].name) {
        int ret = strcmp(argv_exclude_list[i].name, argv_opt_list[j].name);
        if (ret == 0) {
          const size_t name_len = strlen(argv_exclude_list[i].name) + strlen("--") + 1;
          argv_exclude_list[i].name = zalloc(name_len);
          BUG_ON(argv_exclude_list[i].name == NULL);

          ret = snprintf(argv_exclude_list[i].name,
                         name_len,
                         "--%s",
                         argv_opt_list[j].name);
          BUG_ON(ret < 0);

          const size_t val_len = sizeof(char) + strlen("-") + 1;
          argv_exclude_list[i].val = zalloc(val_len);
          BUG_ON(argv_exclude_list[i].val == NULL);

          ret = snprintf(argv_exclude_list[i].val,
                         val_len,
                         "-%s",
                         (char[2]){ (char)argv_opt_list[j].val, '\0' });
          BUG_ON(ret < 0);

          argv_exclude_list[i].has_arg = argv_opt_list[j].has_arg == required_argument;

          break;
        }
      }
    }
  }

  // Create new argv from argv_g
  argv = zalloc((size_t)argc_g * sizeof(char *));
  FATAL_SYSCALL_ON(argv == NULL);
  int argv_idx = 0;
  for (int i = 0; i < argc_g; i++) {
    if (argv_g[i]) {
      bool exclude_arg = false;
      for (size_t j = 0; j < exclude_list_size; j++) {
        if ((strcmp(argv_g[i], argv_exclude_list[j].name) == 0) || (strcmp(argv_g[i], argv_exclude_list[j].val) == 0)) {
          exclude_arg = true;
          // Exclude next arg also, ie. for -f file, file is also excluded
          i = argv_exclude_list[j].has_arg ? (i + 1) : i;
          break;
        }
      }

      if (!exclude_arg) {
        argv[argv_idx] = zalloc(strlen(argv_g[i]) + 1);
        strcpy(argv[argv_idx++], argv_g[i]);
      }
    }
  }

  config_restart_cpcd(argv);

  // Free resources allocated in this function. This is dead code as
  // `config_restart_cpcd` never returns but this makes static code
  // analyser happy
  for (int i = 0; i < argv_idx; i++) {
    free(argv[i]);
  }

  free(argv);

  for (size_t i = 0; i < exclude_list_size; i++) {
    if (argv_exclude_list[i].name) {
      free(argv_exclude_list[i].name);
    }

    if (argv_exclude_list[i].val) {
      free(argv_exclude_list[i].val);
    }
  }
}

void config_exit_cpcd(int status)
{
  PRINT_INFO("Exiting CPCd...");
  sleep_ms(CPCD_REBOOT_TIME_MS / 2); // Wait for logs to be flushed
  exit(status);
}

void config_restart_cpcd(char **argv)
{
  PRINT_INFO("Restarting CPCd...");
  sleep_ms(CPCD_REBOOT_TIME_MS / 2); // Wait for logs to be flushed
  execv("/proc/self/exe", argv);
}

void config_restart_cpcd_without_fw_update_args(void)
{
  argv_exclude_t argv_exclude_list[] = {
    { .name = ARGV_OPT_RESTART_CPCD },
    { .name = ARGV_OPT_FIRMWARE_UPDATE },
    { .name = ARGV_OPT_CONNECT_TO_BOOTLOADER },
  };

  config_restart_cpcd_without_args(argv_exclude_list, sizeof(argv_exclude_list));
}

void config_restart_cpcd_without_bind_arg(void)
{
  argv_exclude_t argv_exclude_list[] = {
    { .name = ARGV_OPT_RESTART_CPCD },
    { .name = ARGV_OPT_BIND },
  };

  config_restart_cpcd_without_args(argv_exclude_list, sizeof(argv_exclude_list));
}

static inline bool is_nul(char c)
{
  return c == '\0';
}

static inline bool is_white_space(char c)
{
  return c == ' ' || c == '\t';
}

static inline bool is_line_break(char c)
{
  return c == '\n' || c == '\r';
}

static inline bool is_comment(char c)
{
  return c == '#';
}

static int32_t non_leading_whitespaces_index(const char *str)
{
  int32_t i = 0;
  while (!is_nul(str[i])) {
    if (!is_white_space(str[i])) {
      break;
    }
    ++i;
  }
  return i;
}

static bool is_comment_or_newline(const char* line)
{
  char c = line[non_leading_whitespaces_index(line)];
  return is_nul(c) || is_line_break(c) || is_comment(c);
}

static void config_parse_multicast_endpoints(const char *input)
{
  long endpoint_id, range_end;
  char *endptr;

  // Clear default values
  memset(config.multicast_endpoints, false, sizeof(config.multicast_endpoints));

  // Skip leading '['
  if (*input++ != '[') {
    FATAL("Config file error: multicast_endpoints must start with '['");
  }

  // Parse numbers/ranges until we hit ']'
  while (*input != ']') {
    // Skip whitespace and commas
    while (is_white_space(*input) || *input == ',') {
      input++;
    }

    // Break if we hit ']'
    if (*input == ']') {
      break;
    }

    // Check for end of string
    if (is_nul(*input)) {
      FATAL("Config file error: multicast_endpoints: missing closing bracket ']'");
    }

    endpoint_id = strtol(input, &endptr, 10);

    // Check if conversion was performed
    if (input == endptr) {
      FATAL("Config file error: multicast_endpoints: invalid character");
    }

    // Check for errors
    if (endpoint_id == LONG_MAX || endpoint_id == LONG_MIN) {
      FATAL("Config file error: multicast_endpoints: errno : %m");
    }

    // Check if value is in valid endpoint range
    if (endpoint_id < 0 || endpoint_id >= SL_CPC_ENDPOINT_MAX_COUNT) {
      FATAL("Config file error: multicast_endpoints: endpoint id %ld is out of valid range [0, %d]", endpoint_id, SL_CPC_ENDPOINT_MAX_COUNT - 1);
    }

    input = endptr;

    // Check for range
    if (*input == '-') {
      input++; // skip '-'
      range_end = strtol(input, &endptr, 10);

      // Check if conversion was performed
      if (input == endptr) {
        FATAL("Config file error: multicast_endpoints: invalid character");
      }

      // Check if value is in valid endpoint range
      if (range_end < endpoint_id || range_end >= SL_CPC_ENDPOINT_MAX_COUNT) {
        FATAL("Config file error: multicast_endpoints: invalid range %ld-%ld", endpoint_id, range_end);
      }

      for (long i = endpoint_id; i <= range_end; ++i) {
        config.multicast_endpoints[i] = true;
      }
      input = endptr;
    } else {
      config.multicast_endpoints[endpoint_id] = true;
    }
  }
}

static void config_parse_config_file(void)
{
  FILE *config_file = NULL;
  char name[128] = { 0 };
  char val[2048] = { 0 };
  char line[2048] = { 0 };
  char *endptr = NULL;
  int tmp_config_file_tracing = 0;

  // By default, all endpoints are enabled for multicast
  memset(config.multicast_endpoints, true, sizeof(config.multicast_endpoints));

  config_file = fopen(config.file_path, "r");

  if (config_file == NULL) {
    FATAL("Could not open the configuration file under: %s, please install the configuration file there or provide a valid path with --conf\n", config.file_path);
  }

  // Iterate through every line of the file
  while (fgets(line, sizeof(line), config_file) != NULL) {
    if (is_comment_or_newline(line)) {
      continue;
    }

    // Extract name=value pair
    if (sscanf(line, "%127[^: ]: %2047[^\r\n#]%*c", name, val) != 2) {
      FATAL("Config file line \"%s\" doesn't respect syntax. Expecting YAML format (key: value). Please refer to the provided cpcd.conf", line);
    }

    if (0 == strcmp(name, "instance_name")) {
      config.instance_name = strdup(val);
      FATAL_ON(config.instance_name == NULL);
    } else if (0 == strcmp(name, "bus_type")) {
      if (0 == strcmp(val, "UART")) {
        config.bus = UART;
      } else if (0 == strcmp(val, "SPI")) {
        config.bus = SPI;
      } else if (0 == strcmp(val, "NETLINK_SDIO")) {
        config.bus = NETLINK_SDIO;
#if defined(ENABLE_SOCKET_DRIVER)
      } else if (0 == strcmp(val, "SOCKET")) {
        config.bus = SOCKET;
#endif
      } else {
        FATAL("Config file error : bad bus_type value\n");
      }
    } else if (0 == strcmp(name, "spi_device_file")) {
      config.spi_file = strdup(val);
      FATAL_ON(config.spi_file == NULL);
    } else if (0 == strcmp(name, "spi_rx_irq_gpio_chip")) {
      config.spi_irq_chip = strdup(val);
    } else if (0 == strcmp(name, "spi_rx_irq_gpio")) {
      config.spi_irq_pin = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "spi_device_bitrate")) {
      config.spi_bitrate = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "bootloader_recovery_pins_enabled")) {
      if (0 == strcmp(val, "true")) {
        config.fwu_recovery_pins_enabled = true;
      } else if (0 == strcmp(val, "false")) {
        config.fwu_recovery_pins_enabled = false;
      } else {
        FATAL("Config file error : bad bootloader_recovery_pins_enabled value");
      }
    } else if (0 == strcmp(name, "bootloader_wake_gpio_chip")) {
      config.fwu_wake_chip = strdup(val);
    } else if (0 == strcmp(name, "bootloader_wake_gpio")) {
      config.fwu_spi_wake_pin = (int)strtol(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "bootloader_reset_gpio_chip")) {
      config.fwu_reset_chip = strdup(val);
    } else if (0 == strcmp(name, "bootloader_reset_gpio")) {
      config.fwu_spi_reset_pin = (int)strtol(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "uart_device_file")) {
      config.uart_file = strdup(val);
      FATAL_ON(config.uart_file == NULL);
    } else if (0 == strcmp(name, "uart_device_baud")) {
      config.uart_baudrate = (unsigned int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Bad config line \"%s\"", line);
      }
    } else if (0 == strcmp(name, "uart_hardflow")) {
      if (0 == strcmp(val, "true")) {
        config.uart_hardflow = true;
      } else if (0 == strcmp(val, "false")) {
        config.uart_hardflow = false;
      } else {
        FATAL("Config file error : bad UART_HARDFLOW value");
      }
    } else if (0 == strcmp(name, "noop_keep_alive")) {
      if (0 == strcmp(val, "true")) {
        config.use_noop_keep_alive = true;
      } else if (0 == strcmp(val, "false")) {
        config.use_noop_keep_alive = false;
      } else {
        FATAL("Config file error : bad noop_keep_alive value");
      }
    } else if (0 == strcmp(name, "stdout_trace")) {
      if (0 == strcmp(val, "true")) {
        config.stdout_tracing = true;
      } else if (0 == strcmp(val, "false")) {
        config.stdout_tracing = false;
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
        config.enable_frame_trace = true;
      } else if (0 == strcmp(val, "false")) {
        config.enable_frame_trace = false;
      } else {
        FATAL("Config file error : bad enable_frame_trace value");
      }
    } else if (0 == strcmp(name, "disable_encryption")) {
      if (0 == strcmp(val, "true")) {
        config.use_encryption = false;
      } else if (0 == strcmp(val, "false")) {
        config.use_encryption = true;
      } else {
        FATAL("Config file error : bad disable_encryption value");
      }
    } else if (0 == strcmp(name, "reset_sequence")) {
      if (0 == strcmp(val, "true")) {
        config.reset_sequence = true;
      } else if (0 == strcmp(val, "false")) {
        config.reset_sequence = false;
      } else {
        FATAL("Config file error : bad reset_sequence value");
      }
    } else if (0 == strcmp(name, "traces_folder")) {
      config.traces_folder = strdup(val);
      FATAL_ON(config.traces_folder == NULL);
    } else if (0 == strcmp(name, "multicast_endpoints")) {
      config_parse_multicast_endpoints(val);
    } else if (0 == strcmp(name, "rlimit_nofile")) {
      config.rlimit_nofile = (int)strtoul(val, &endptr, 10);
      if (*endptr != '\0') {
        FATAL("Config file error : bad rlimit_nofile value");
      }
    } else if (0 == strcmp(name, "enable_lttng_tracing")) {
#ifdef COMPILE_LTTNG
      if (0 == strcmp(val, "true")) {
        config.lttng_tracing = true;
      } else if (0 == strcmp(val, "false")) {
        config.lttng_tracing = false;
      } else {
        fprintf(stderr, "Config file error : bad enable_lttng_tracing value\n");
      }
#else
      fprintf(stderr, "Config file error : lttng support is not compiled with this executable\n");
#endif
    } else if (0 == strcmp(name, "binding_key_file")) {
      if (config.binding_key_override == false) {
        config.binding_key_file = strdup(val);
        FATAL_SYSCALL_ON(config.binding_key_file == NULL);
      }
    } else {
      WARN("Configuration file error : key \"%s\" not recognized", name);
    }
  }

  config.file_tracing = tmp_config_file_tracing;

  fclose(config_file);
}

/*
 * Running two instances of the daemon over the same hardware device must be prohibited.
 * In order to detect when a daemon is bound to a device, file locks are used.
 */
static void prevent_device_collision(const char* const device_name)
{
  int tmp_fd = open(device_name, O_RDWR | O_CLOEXEC);

  // Try to apply a cooperative exclusive file lock on the device file. Don't block
  int ret = flock(tmp_fd, LOCK_EX | LOCK_NB);

  if (ret == 0) {
    // The device file is free to use, leave this file descriptor open
    // to preserve the lock.
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

  // Create datagram socket for control
  ctrl_sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  FATAL_SYSCALL_ON(ctrl_sock_fd < 0);

  // Clear struct for portability
  memset(&name, 0, sizeof(name));

  name.sun_family = AF_UNIX;

  // Create the control socket path
  {
    int nchars;
    const size_t size = sizeof(name.sun_path) - sizeof('\0');

    nchars = snprintf(name.sun_path, size, "%s/cpcd/%s/ctrl.cpcd.sock", config.socket_folder, instance_name);

    // Make sure the path fitted entirely
    FATAL_ON(nchars < 0 || (size_t) nchars >= size);
  }

  // Try to connect to the socket in order to see if we collide with another daemon
  {
    int ret;

    ret = connect(ctrl_sock_fd, (const struct sockaddr *) &name, sizeof(name));

    (void) close(ctrl_sock_fd);

    if (ret == 0) {
      FATAL("Another daemon instance is already running with the same instance name : %s.", name.sun_path);
    } else {
      // good to go
    }
  }
}

static void config_validate_configuration(void)
{
  // Validate bus configuration
  {
    if (config.bus == SPI) {
      if (config.spi_file == NULL) {
        FATAL("SPI device file missing");
      }

      if (config.spi_irq_chip == NULL) {
        FATAL("spi_irq_chip is requiered");
      }

      prevent_device_collision(config.spi_file);
    } else if (config.bus == UART) {
      if (config.uart_file == NULL) {
        FATAL("UART device file missing");
      }

      prevent_device_collision(config.uart_file);
    } else if (config.bus == NETLINK_SDIO) {
#if defined(ENABLE_SOCKET_DRIVER)
    } else if (config.bus == SOCKET) {
      // TODO check
#endif
    } else {
      FATAL("Invalid bus configuration.");
    }
  }

  prevent_instance_collision(config.instance_name);

  if (config.operation_mode == MODE_FIRMWARE_UPDATE) {
    if (access(config.fwu_file, F_OK | R_OK) != 0) {
      FATAL("Firmware update file (%s) : %m", config.fwu_file);
    }
  }

  if (config.use_encryption) {
#if !defined(ENABLE_ENCRYPTION)
    FATAL("Use of encryption was requested, but the daemon was not compiled with -DENABLE_ENCRYPTION");
#endif
  }

  if (config.use_encryption && config.operation_mode != MODE_BINDING_UNBIND) {
    if (config.binding_key_file == NULL) {
      FATAL("No binding key file provided needed for security. Provide BINDING_KEY_FILE in the configuration file or use the --key argument. ");
    }
  }

  if (config.operation_mode == MODE_BINDING_ECDH) {
    char *binding_key_file_copy = strdup(config.binding_key_file);
    FATAL_SYSCALL_ON(binding_key_file_copy == NULL);
    char *binding_key_folder = dirname(binding_key_file_copy);

    if (strcmp(".", binding_key_folder) != 0) {
      PRINT_INFO("Creating binding key folder %s", binding_key_folder);
      int ret = recursive_mkdir(binding_key_folder, strlen(binding_key_folder), 0700);
      if (ret != 0) {
        FATAL("Failed to create binding key folder %m, %s", binding_key_folder);
      }

      if (access(binding_key_folder, W_OK) != 0 ) {
        FATAL("Binding key folder (%s) : %m", binding_key_folder);
      }
    }

    free(binding_key_file_copy);
  }

  if (config.restart_cpcd) {
    switch (config.operation_mode) {
      case MODE_FIRMWARE_UPDATE:
      case MODE_BINDING_ECDH:
      case MODE_BINDING_PLAIN_TEXT:
        break;
      default:
        FATAL("--restart-cpcd only supported with --firmware-update or --bind");
    }
  }

  if (config.fwu_connect_to_bootloader && config.operation_mode != MODE_FIRMWARE_UPDATE) {
    FATAL("--connect-to-bootloader only supported with --firmware-update");
  }

  if (config.fwu_connect_to_bootloader && config.fwu_enter_bootloader) {
    FATAL("Cannot select both --enter-bootloader and --connect-to-bootloader");
  }

  if (config.fwu_recovery_pins_enabled) {
    if (config.application_version_validation != NULL) {
      FATAL("-a/--app-version is not compatible with bootloader_recovery_pins_enabled");
    }

    // this is to support calls to reboot_secondary_with_pins_into_bootloader()
    if (config.fwu_spi_wake_pin == -1 || config.fwu_spi_reset_pin == -1) {
      FATAL("bootloader_wake_gpio and bootloader_reset_gpio required "
            "but not set in config");
    }

    if (config.fwu_wake_chip == NULL || config.fwu_reset_chip == NULL) {
      FATAL("Recovery pins are enabled, values are required for "
            "bootloader_wake_gpio_chip and bootloader_reset_gpio_chip");
    }
  }

  if (config.fwu_enter_bootloader) {
    config.operation_mode = MODE_FIRMWARE_UPDATE;
  }

  if (config.file_tracing) {
    init_file_logging();
  }

  if (config.stats_interval > 0) {
    init_stats_logging();
  }
}

static void config_set_rlimit_nofile(void)
{
  struct rlimit limit;
  int ret;

  // Make sure RLIMIT_NOFILE (number of concurrent opened file descriptor)
  // is at least rlimit_nofile

  ret = getrlimit(RLIMIT_NOFILE, &limit);
  FATAL_SYSCALL_ON(ret < 0);

  if (limit.rlim_cur < (rlim_t)config.rlimit_nofile) {
    if ((rlim_t)config.rlimit_nofile > limit.rlim_max) {
      FATAL("The OS doesn't support our requested RLIMIT_NOFILE value");
    }

    limit.rlim_cur = (rlim_t)config.rlimit_nofile;

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
  fprintf(stream, "  cpcd -h/--help : prints this message.\n");
  fprintf(stream, "  cpcd -c/--conf <file> : manually specify the config file.\n");
  fprintf(stream, "  cpcd -v/--version : get the version of the daemon and exit.\n");
  fprintf(stream, "  cpcd -p/--secondary-versions : get all secondary versions (protocol, cpc, app) and exit.\n");
  fprintf(stream, "  cpcd -a/--app-version <version> : specify the application version to match.\n");
  fprintf(stream, "  cpcd -f/--firmware-update <file> : specify the .gbl file to update the secondary's firmware with.\n");
  fprintf(stream, "  cpcd -r/--restart-cpcd : restart the daemon. Only supported with --firmware-update or --bind.\n");
  fprintf(stream, "  cpcd -e/--enter-bootloader : restart the secondary device in bootloader and exit.\n");
  fprintf(stream, "  cpcd -l/--connect-to-bootloader : connect directly to bootloader. Only supported with --firmware-update.\n");
  fprintf(stream, "  cpcd -b/--bind <method> : bind to the secondary using the provided key in the config file or the --key argument. Currently supported methods: ecdh or plain-text.\n");
  fprintf(stream, "  cpcd -u/--unbind : attempt to unbind from the secondary.\n");
  fprintf(stream, "  cpcd -k/--key <file> : provide the binding keyfile to read from or write to, this argument will override the BINDING_KEY_FILE config.\n");
  fprintf(stream, "  cpcd -s/--print-stats <interval> : print debug statistics to traces. Must provide a given interval in seconds.\n");
  fprintf(stream, "  cpcd -w/--wireless-kit-ip <ipaddress> : validates board controller vcom configuration.\n");
  fprintf(stream, "  cpcd -t/--uart-validation <test> : provide test option to run: 1 -> RX/TX, 2 -> RTS/CTS.\n");
  exit(exit_code);
}
