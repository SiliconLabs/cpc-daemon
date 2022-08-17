/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - UART Validation Mode
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

#include <pthread.h>
#include <unistd.h>

#include "modes/uart_validation.h"
#include "server_core/core/core.h"
#include "server_core/server_core.h"
#include "driver/driver_uart.h"
#include "misc/config.h"
#include "misc/logging.h"
#include "misc/sleep.h"

#define TIMEOUT_SECONDS         5
#define TIME_BETWEEN_RETRIES_US 1000000

extern pthread_t driver_thread;
extern pthread_t server_core_thread;

/* Flag set when waiting on external reset */
static bool wait_on_reset_external;

/* Flag set when external reset status is received */
static bool reset_external_received;

/* Flag set when waiting on software reset */
static bool wait_on_reset_software;

/* Flag set when software reset status is received */
static bool reset_software_received;

/* Flag set when secondary cpc version is received */
static bool secondary_cpc_version_received;

/* Flag set when fc validation value is received */
static bool fc_validation_value_received;

/* Flow control validation value */
static uint32_t fc_validation_value;

/* Flag set when uframe processing is received */
static bool uframe_processing_received;

/* Flag set when enter irq is received */
static bool enter_irq_received;

/* Flag set when noop is received */
static bool noop_received;

/* Main tests */
static void test_1_rx_tx(void);
static void test_2_rts_cts(void);

/* Sub tests */
static void open_uart_port_subtest(bool flowcontrol);
static void reset_external_subtest(void);
static void reset_software_subtest(void);
static void get_secondary_cpc_version_subtest(void);
static void enable_uframe_processing_subtest(bool enable);
static void enter_irq_subtest(uint32_t start_in_ms, uint32_t end_in_ms);
static void send_noop_subtest(void);
static uint32_t send_data_subtest(void);
static uint32_t get_fc_validation_value_subtest(void);

/* Helpers */
static void compare_fc_validation_values(uint32_t reference_value, uint32_t received_value);
static void wait(uint32_t mseconds);

/* Callbacks */
static void reset_software_callback(sl_cpc_system_command_handle_t *handle,
                                    sl_status_t status,
                                    sl_cpc_system_status_t reset_status);

static void get_secondary_cpc_version_callback(sl_cpc_system_command_handle_t *handle,
                                               sl_cpc_property_id_t property_id,
                                               void* property_value,
                                               size_t property_length,
                                               sl_status_t status);

static void get_fc_validation_value_callback(sl_cpc_system_command_handle_t *handle,
                                             sl_cpc_property_id_t property_id,
                                             void* property_value,
                                             size_t property_length,
                                             sl_status_t status);

static void enable_uframe_processing_callback(sl_cpc_system_command_handle_t *handle,
                                              sl_cpc_property_id_t property_id,
                                              void* property_value,
                                              size_t property_length,
                                              sl_status_t status);

static void enter_irq_callback(sl_cpc_system_command_handle_t *handle,
                               sl_cpc_property_id_t property_id,
                               void* property_value,
                               size_t property_length,
                               sl_status_t status);

static void noop_callback(sl_cpc_system_command_handle_t *handle,
                          sl_status_t status);

/* External functions */
__attribute__((noreturn)) void software_graceful_exit(void);

void run_uart_validation(void)
{
  int test_option = (int) *config_uart_validation_test_option;
  switch (test_option) {
    case '1':
      test_1_rx_tx();
      break;
    case '2':
      test_2_rts_cts();
      break;
    default:
      BUG("Invalid UART validation test option: %c, see --help", test_option);
  }

  software_graceful_exit();
}

bool uart_validation_reset_requested(sl_cpc_system_status_t status)
{
  if (wait_on_reset_external) {
    TRACE_UART_VALIDATION("Received reset reason : %u", status);
    reset_external_received = true;
    return true;
  }

  if (wait_on_reset_software) {
    TRACE_UART_VALIDATION("Received reset reason : %u", status);
    return true;
  }

  return false;
}

/***************************************************************************//**
 * Main tests
 ******************************************************************************/
static void test_1_rx_tx(void)
{
  PRINT_INFO("Running UART validation test #1 - RX/TX");

  open_uart_port_subtest(false);

  PRINT_INFO("Validating Host RX <-> Secondary TX...");
  reset_external_subtest();

  PRINT_INFO("Validating Host TX/RX <-> Secondary RX/TX...");
  reset_software_subtest();
}

static void test_2_rts_cts(void)
{
  PRINT_INFO("Running UART validation test #2 - RTS/CTS");

  open_uart_port_subtest(true);

  PRINT_INFO("Validating Host TX/RX <-> Secondary RX/TX...");
  reset_software_subtest();
  get_secondary_cpc_version_subtest();

  PRINT_INFO("Validating Host CTS <-> Secondary RTS...");
  enable_uframe_processing_subtest(true);
  uint32_t irq_start_in_ms = 500, irq_end_in_ms = 3000;
  enter_irq_subtest(irq_start_in_ms, irq_end_in_ms);
  wait(irq_start_in_ms + irq_start_in_ms);
  uint32_t fc_validation_value = send_data_subtest();
  wait(irq_end_in_ms);
  uint32_t received_fc_validation_value = get_fc_validation_value_subtest();
  enable_uframe_processing_subtest(false);
  compare_fc_validation_values(fc_validation_value, received_fc_validation_value);

  PRINT_INFO("Validating Host RTS <-> Secondary CTS...");
  send_noop_subtest();
}

/***************************************************************************//**
 * Sub tests
 ******************************************************************************/
static void open_uart_port_subtest(bool flowcontrol)
{
  TRACE_UART_VALIDATION("Opening UART port");
  int fd_socket_driver_core;
  if (config_bus == UART) {
    // Bypass configuration for flow control: set to true to determine that RTS/CTS pins are not connected properly
    driver_thread = driver_uart_init(&fd_socket_driver_core, config_uart_file, config_uart_baudrate, flowcontrol);
  } else {
    BUG("Invalid bus_type, should be UART, see cpcd.conf");
  }

  // Disable reset sequence because we want to do it ourselves
  config_reset_sequence = false;
  server_core_thread = server_core_init(fd_socket_driver_core, SERVER_CORE_MODE_NORMAL);
}

static void reset_external_subtest(void)
{
  PRINT_INFO("Reset the Secondary and press ENTER");
  wait_on_reset_external = true;
  getchar();

  uint8_t timeout_seconds = TIMEOUT_SECONDS;
  while (1) {
    if (reset_external_received) {
      TRACE_UART_VALIDATION("Received external reset ack");
      PRINT_INFO("SUCCESS : Host RX is connected to Secondary TX");
      break;
    }

    if (timeout_seconds-- == 0) {
      FATAL("FAILURE : Host RX is not connected to Secondary TX");
    }

    sleep_s(1);
  }
}

static void reset_software_subtest(void)
{
  uint8_t timeout_seconds = TIMEOUT_SECONDS;
  TRACE_UART_VALIDATION("Sending software reset command");
  wait_on_reset_software = true;
  sl_cpc_system_cmd_reboot(reset_software_callback,
                           TIMEOUT_SECONDS,
                           TIME_BETWEEN_RETRIES_US);

  while (1) {
    if (reset_software_received) {
      TRACE_UART_VALIDATION("Received software reset ack");
      PRINT_INFO("SUCCESS : Host TX/RX is connected to Secondary RX/TX");
      break;
    }

    if (timeout_seconds-- == 0) {
      FATAL("FAILURE : Host TX/RX is not connected to Secondary RX/TX");
    }

    sleep_s(1);
  }
}

static void get_secondary_cpc_version_subtest(void)
{
  uint8_t timeout_seconds = TIMEOUT_SECONDS;
  TRACE_UART_VALIDATION("Sending get Secondary CPC version command");
  sl_cpc_system_cmd_property_get(get_secondary_cpc_version_callback,
                                 PROP_SECONDARY_CPC_VERSION,
                                 TIMEOUT_SECONDS,
                                 TIME_BETWEEN_RETRIES_US,
                                 false);

  while (1) {
    if (secondary_cpc_version_received) {
      TRACE_UART_VALIDATION("Received Secondary CPC version");
      break;
    }

    if (timeout_seconds-- == 0) {
      FATAL("TIMEOUT : Check TX/RX pins");
    }

    sleep_s(1);
  }
}

static void enable_uframe_processing_subtest(bool enable)
{
  uint8_t timeout_seconds = TIMEOUT_SECONDS;

  if (enable) {
    TRACE_UART_VALIDATION("Sending enable uframes processing command");
  } else {
    TRACE_UART_VALIDATION("Sending disable uframes processing command");
  }

  sl_cpc_system_cmd_property_set(enable_uframe_processing_callback,
                                 TIMEOUT_SECONDS,
                                 TIME_BETWEEN_RETRIES_US,
                                 PROP_UFRAME_PROCESSING,
                                 &enable,
                                 sizeof(enable),
                                 false);

  while (1) {
    if (uframe_processing_received) {
      if (enable) {
        TRACE_UART_VALIDATION("Received enable uframes processing ack");
      } else {
        TRACE_UART_VALIDATION("Received disable uframes processing ack");
      }
      uframe_processing_received = false;
      break;
    }

    if (timeout_seconds-- == 0) {
      FATAL("TIMEOUT : Check TX/RX pins");
    }

    sleep_s(1);
  }
}

static void enter_irq_subtest(uint32_t start_in_ms, uint32_t end_in_ms)
{
  uint8_t timeout_seconds = TIMEOUT_SECONDS;
  sl_cpc_system_enter_irq_cmd_t enter_irq_cmd = { .start_in_ms = start_in_ms, .end_in_ms = end_in_ms };

  TRACE_UART_VALIDATION("Sending Enter IRQ command, start in %d ms, end in %d ms", start_in_ms, end_in_ms);
  sl_cpc_system_cmd_property_set(enter_irq_callback,
                                 TIMEOUT_SECONDS,
                                 TIME_BETWEEN_RETRIES_US,
                                 PROP_ENTER_IRQ,
                                 &enter_irq_cmd,
                                 sizeof(enter_irq_cmd),
                                 false);
  while (1) {
    if (enter_irq_received) {
      TRACE_UART_VALIDATION("Received Enter IRQ ack");
      break;
    }

    if (timeout_seconds-- == 0) {
      FATAL("TIMEOUT : Check TX/RX pins");
    }

    sleep_s(1);
  }
}

static uint32_t send_data_subtest(void)
{
  const uint8_t data[] = { 2, 4, 8, 16, 32, 64 };
  uint32_t sum = 0;

  for (uint32_t i = 0; i < sizeof(data); i++) {
    sum += data[i];
    TRACE_UART_VALIDATION("Sending data: %d", data[i]);
    core_write(SL_CPC_ENDPOINT_SYSTEM, &data[i], 1, SL_CPC_FLAG_UNNUMBERED_INFORMATION);
  }

  TRACE_UART_VALIDATION("FC validation value: %d", sum);
  return sum;
}

static uint32_t get_fc_validation_value_subtest(void)
{
  uint8_t timeout_seconds = TIMEOUT_SECONDS;

  TRACE_UART_VALIDATION("Sending get FC validation value command");
  sl_cpc_system_cmd_property_get(get_fc_validation_value_callback,
                                 PROP_FC_VALIDATION_VALUE,
                                 TIMEOUT_SECONDS,
                                 TIME_BETWEEN_RETRIES_US,
                                 false);

  while (1) {
    if (fc_validation_value_received) {
      TRACE_UART_VALIDATION("Received FC validation value: %d", fc_validation_value);
      break;
    }

    if (timeout_seconds-- == 0) {
      FATAL("TIMEOUT : Check TX/RX pins");
    }

    sleep_s(1);
  }

  return fc_validation_value;
}

static void send_noop_subtest(void)
{
  bool rts = false;
  uint8_t timeout_seconds = TIMEOUT_SECONDS;

  TRACE_UART_VALIDATION("Deasserting RTS pin");
  driver_uart_assert_rts(rts);

  TRACE_UART_VALIDATION("Sending noop command");
  sl_cpc_system_cmd_noop(noop_callback,
                         TIMEOUT_SECONDS,
                         TIME_BETWEEN_RETRIES_US);

  while (1) {
    if (noop_received) {
      if (rts) {
        TRACE_UART_VALIDATION("Received noop ack after RTS pin was asserted");
        PRINT_INFO("SUCCESS : Host RTS is connected to Secondary CTS");
      } else {
        TRACE_UART_VALIDATION("Received noop ack while RTS pin was deasserted");
        FATAL("FAILURE : Host RTS is not connected to Secondary CTS");
      }
      break;
    }

    if (timeout_seconds-- == 0) {
      FATAL("TIMEOUT : Check RTS/CTS pins");
    }

    if (timeout_seconds == 0) {
      rts = true;
      driver_uart_assert_rts(rts);
      TRACE_UART_VALIDATION("Asserting RTS pin");
    }

    sleep_s(1);
  }
}

/***************************************************************************//**
 * Helpers
 ******************************************************************************/
static void compare_fc_validation_values(uint32_t reference_value, uint32_t received_value)
{
  if (reference_value == received_value) {
    TRACE_UART_VALIDATION("FC validation value (%d) matches received FC validation value (%d)", reference_value, received_value);
    PRINT_INFO("SUCCESS : Host CTS is connected to Secondary RTS");
  } else {
    TRACE_UART_VALIDATION("FC validation value (%d) does not not match received FC validation value (%d)", reference_value, received_value);
    FATAL("FAILURE : Host CTS is not connected to Secondary RTS");
  }
}

static void wait(uint32_t mseconds)
{
  TRACE_UART_VALIDATION("Wait %d ms", mseconds);
  sleep_ms(mseconds);
}

/***************************************************************************//**
 * Callbacks
 ******************************************************************************/
static void reset_software_callback(sl_cpc_system_command_handle_t *handle,
                                    sl_status_t status,
                                    sl_cpc_system_status_t reset_status)
{
  (void) handle;

  if (status == SL_STATUS_OK && reset_status == SL_STATUS_OK) {
    reset_software_received = true;
  } else {
    FATAL("Unhandled status: %d with reset_status: %d", status, reset_status);
  }
}

static void get_secondary_cpc_version_callback(sl_cpc_system_command_handle_t *handle,
                                               sl_cpc_property_id_t property_id,
                                               void* property_value,
                                               size_t property_length,
                                               sl_status_t status)
{
  (void) handle;

  uint32_t *version = (uint32_t*)property_value;

  if ( (property_id != PROP_SECONDARY_CPC_VERSION)
       || (status != SL_STATUS_OK && status != SL_STATUS_IN_PROGRESS)
       || (property_value == NULL || property_length != 3 * sizeof(uint32_t))) {
    FATAL("Cannot get Secondary CPC version (obsolete firmware?)");
  }

  TRACE_UART_VALIDATION("Secondary CPC v%d.%d.%d", version[0], version[1], version[2]);
  secondary_cpc_version_received = true;
}

static void get_fc_validation_value_callback(sl_cpc_system_command_handle_t *handle,
                                             sl_cpc_property_id_t property_id,
                                             void* property_value,
                                             size_t property_length,
                                             sl_status_t status)
{
  (void) handle;
  (void) property_id;
  (void) property_value;
  (void) property_length;

  if (status == SL_STATUS_OK) {
    fc_validation_value_received = true;
    fc_validation_value = *(uint32_t*)property_value;
  } else {
    FATAL("Cannot get fc validation value (obsolete firmware?)");
  }
}

static void enable_uframe_processing_callback(sl_cpc_system_command_handle_t *handle,
                                              sl_cpc_property_id_t property_id,
                                              void* property_value,
                                              size_t property_length,
                                              sl_status_t status)
{
  (void) handle;
  (void) property_id;
  (void) property_value;
  (void) property_length;

  if (status == SL_STATUS_OK) {
    uframe_processing_received = true;
  } else {
    FATAL("Cannot set uframe processing (obsolete firmware?)");
  }
}

static void enter_irq_callback(sl_cpc_system_command_handle_t *handle,
                               sl_cpc_property_id_t property_id,
                               void* property_value,
                               size_t property_length,
                               sl_status_t status)
{
  (void) handle;
  (void) property_id;
  (void) property_value;
  (void) property_length;

  if (status == SL_STATUS_OK) {
    enter_irq_received = true;
  } else {
    FATAL("Cannot set enter irq (obsolete firmware?)");
  }
}

static void noop_callback(sl_cpc_system_command_handle_t *handle,
                          sl_status_t status)
{
  (void) handle;

  if (status == SL_STATUS_OK) {
    noop_received = true;
  } else {
    FATAL("Did not receive noop, status = %d", status);
  }
}
