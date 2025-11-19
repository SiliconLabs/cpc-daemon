/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Logging Interface
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

#ifndef LOGGING_H
#define LOGGING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <cpcd/config.h>
#include <cpcd/exit.h>

/// Struct representing CPC Core debug counters.
typedef struct {
  uint32_t endpoint_opened;
  uint32_t endpoint_closed;
  uint32_t rxd_frame;
  uint32_t rxd_valid_iframe;
  uint32_t rxd_valid_uframe;
  uint32_t rxd_valid_sframe;
  uint32_t rxd_data_frame_dropped;
  uint32_t txd_reject_destination_unreachable;
  uint32_t txd_reject_error_fault;
  uint32_t txd_completed;
  uint32_t retxd_data_frame;
  uint32_t driver_error;
  uint32_t driver_packet_dropped;
  uint32_t invalid_header_checksum;
  uint32_t invalid_payload_checksum;
} core_debug_counters_t;

void logging_init(void);

void init_file_logging(void);

void init_stats_logging(void);

void logging_kill(void);

void trace(bool timestamp, const char* string, ...) __attribute__((format(printf, 2, 3)));

void trace_frame(const char* string, const void* buffer, size_t len);

void logging_driver_print_stats(void);

extern core_debug_counters_t primary_core_debug_counters;
extern core_debug_counters_t secondary_core_debug_counters;

#define EVENT_COUNTER_INIT()         (memset(&sl_cpc_core_debug_counters, sizeof(sl_cpc_core_debug_counters), 0))
#define EVENT_COUNTER_INC(counter)   ((primary_core_debug_counters.counter)++)

#ifdef COMPILE_LTTNG
#include <lttng/tracef.h>
#define LTTNG_TRACE(string, ...)  tracef(string, ##__VA_ARGS__)
#else
#define LTTNG_TRACE(string, ...) (void)0
#endif

#define TRACE_LEVEL_ENABLED(level) (config.trace_level >= (level))

#define TRACE_WITH_LEVEL(level, string, ...) \
  do {                                       \
    if (TRACE_LEVEL_ENABLED(level)) {        \
      LTTNG_TRACE(string, ##__VA_ARGS__);    \
      trace(true, string, ##__VA_ARGS__);    \
    }                                        \
  } while (0)

#define TRACE_WITH_LEVEL_NO_TIMESTAMP(level, string, ...) \
  do {                                                    \
    if (TRACE_LEVEL_ENABLED(level)) {                     \
      LTTNG_TRACE(string, ##__VA_ARGS__);                 \
      trace(false, string, ##__VA_ARGS__);                \
    }                                                     \
  } while (0)

// Level-specific macros
#define TRACE_ERROR(string, ...)                                 TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_ERROR, "ERROR : " string "\n", ##__VA_ARGS__)
#define TRACE_WARN(string, ...)                                  TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_WARN, "WARNING : " string "\n", ##__VA_ARGS__)
#define PRINT_INFO(string, ...)                                  TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_INFO, "Info : " string "\n", ##__VA_ARGS__)
#define TRACE_DEBUG(string, ...)                                 TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, string, ##__VA_ARGS__)
#define TRACE_FRAME(string, buffer, length)           \
  do {                                                \
    if (TRACE_LEVEL_ENABLED(CPC_TRACE_LEVEL_FRAME)) { \
      trace_frame(string, buffer, length);            \
    }                                                 \
  } while (0)

// Component traces (all at DEBUG level)
#define TRACE_NAKED(string, ...)                                 TRACE_WITH_LEVEL_NO_TIMESTAMP(CPC_TRACE_LEVEL_DEBUG, string, ##__VA_ARGS__)
#define TRACE_DRIVER(string, ...)                                TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Driver : " string "\n", ##__VA_ARGS__)
#define TRACE_GPIO(string, ...)                                  TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Gpio : " string "\n", ##__VA_ARGS__)
#define TRACE_CORE(string, ...)                                  TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : " string "\n", ##__VA_ARGS__)
#define TRACE_SECURITY(string, ...)                              TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Security : " string "\n", ##__VA_ARGS__)
#define TRACE_SERVER(string, ...)                                TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Server : " string "\n", ##__VA_ARGS__)
#define TRACE_SYSTEM(string, ...)                                TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "System : " string "\n", ##__VA_ARGS__)
#define TRACE_UART_VALIDATION(string, ...)                       TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "UART VALIDATION : " string "\n", ##__VA_ARGS__)
#define TRACE_RESET(string, ...)                                 TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Reset Sequence : " string "\n", ##__VA_ARGS__)
#define TRACE_XMODEM(string, ...)                                TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "XMODEM : " string "\n", ##__VA_ARGS__)
#define TRACE_EZSP_SPI(string, ...)                              TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "EZSPI-SPI : " string "\n", ##__VA_ARGS__)
#define trace_lib(string, ...)                                   TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Lib : " string "\n", ##__VA_ARGS__)

// ASSERT traces (ERROR level)
#define TRACE_ASSERT(string, ...)                                TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_ERROR, "*** ASSERT *** : " string, ##__VA_ARGS__)

// Core trace macros (all at DEBUG level)
#define TRACE_CORE_EVENT(event, string, ...)                     do { EVENT_COUNTER_INC(event); TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : " string "\n", ##__VA_ARGS__); } while (0)
#define TRACE_CORE_OPEN_ENDPOINT(ep_id)                          TRACE_CORE_EVENT(endpoint_opened, "open ep #%u", ep_id)
#define TRACE_CORE_CLOSE_ENDPOINT(ep_id)                         TRACE_CORE_EVENT(endpoint_closed, "close ep #%u", ep_id)
#define TRACE_CORE_RXD_VALID_IFRAME()                            TRACE_CORE_EVENT(rxd_valid_iframe, "rxd iframe with valid header checksum")
#define TRACE_CORE_RXD_VALID_UFRAME()                            TRACE_CORE_EVENT(rxd_valid_uframe, "rxd uframe with valid header checksum")
#define TRACE_CORE_RXD_VALID_SFRAME()                            TRACE_CORE_EVENT(rxd_valid_sframe, "rxd sframe with valid header checksum")
#define TRACE_CORE_RXD_DATA_FRAME_DROPPED()                      TRACE_CORE_EVENT(rxd_data_frame_dropped, "rxd data frame dropped")
#define TRACE_CORE_TXD_REJECT_DESTINATION_UNREACHABLE()          TRACE_CORE_EVENT(txd_reject_destination_unreachable, "txd reject destination unreachable")
#define TRACE_CORE_TXD_REJECT_ERROR_FAULT()                      TRACE_CORE_EVENT(txd_reject_error_fault, "txd reject error fault")
#define TRACE_CORE_INVALID_HEADER_CHECKSUM()                     TRACE_CORE_EVENT(invalid_header_checksum, "invalid header checksum")
#define TRACE_CORE_INVALID_PAYLOAD_CHECKSUM()                    TRACE_CORE_EVENT(invalid_payload_checksum, "invalid payload checksum")
#define TRACE_CORE_TXD_TRANSMIT_COMPLETED()                      TRACE_CORE_EVENT(txd_completed, "txd transmit completed")

// Frame-specific traces (all at FRAME level)
#define TRACE_SERVER_RXD_FRAME(buffer, len)                      TRACE_FRAME("Server : rxd frame : ", buffer, len)
#define TRACE_SERVER_TXD_FRAME(buffer, len)                      TRACE_FRAME("Server : txd frame : ", buffer, len)
#define TRACE_DRIVER_RXD_FRAME(buffer, len)                      TRACE_FRAME("Driver : rxd frame : ", buffer, len)
#define TRACE_CORE_RXD_FRAME(buffer, len)                        do { EVENT_COUNTER_INC(rxd_frame); TRACE_FRAME("Core : rxd frame : ", buffer, len); } while (0)

// Driver-specific traces (all at DEBUG level)
#define TRACE_CORE_DRIVER_READ_ERROR()                           TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : driver read error\n")
#define TRACE_CORE_DRIVER_PACKET_DROPPED()                       TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : driver packet dropped\n")
#define TRACE_DRIVER_INVALID_HEADER_CHECKSUM()                   do { EVENT_COUNTER_INC(invalid_header_checksum); TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Driver : invalid header checksum in driver\n"); } while (0)

// All the endpoint traces (all at DEBUG level)
#define TRACE_ENDPOINT_RXD_FRAME(ep)                             TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd frame\n", ep->id)
#define TRACE_ENDPOINT_RXD_DATA_FRAME(ep)                        TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd data frame\n", ep->id)
#define TRACE_ENDPOINT_RXD_DATA_FRAME_QUEUED(ep)                 TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd data frame queued\n", ep->id)
#define TRACE_ENDPOINT_RXD_DATA_FRAME_DROPPED(ep)                TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd data frame dropped\n", ep->id)
#define TRACE_ENDPOINT_RXD_SUPERVISORY_FRAME(ep)                 TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd supervisory frame\n", ep->id)
#define TRACE_ENDPOINT_RXD_SUPERVISORY_PROCESSED(ep)             TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd supervisory processed\n", ep->id)
#define TRACE_ENDPOINT_RXD_SUPERVISORY_DROPPED(ep)               TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd supervisory dropped\n", ep->id)
#define TRACE_ENDPOINT_RXD_UNNUMBERED_FRAME(ep)                  TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd unnumbered frame\n", ep->id)
#define TRACE_ENDPOINT_RXD_UNNUMBERED_DROPPED(ep, reason)        TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%d: unnumbered frame dropped : %s\n", ((ep == NULL) ? -1 : (signed) ep->id), reason)
#define TRACE_ENDPOINT_RXD_UNNUMBERED_PROCESSED(ep)              TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: unnumbered frame processed\n", ep->id)
#define TRACE_ENDPOINT_RXD_DUPLICATE_DATA_FRAME(ep)              TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd duplicate data frame\n", ep->id)
#define TRACE_ENDPOINT_RXD_ACK(ep, ack)                          TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd ack %u\n", ep->id, ack)
#define TRACE_ENDPOINT_RXD_REJECT_DESTINATION_UNREACHABLE(ep)    TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd reject destination unreachable\n", ep->id)
#define TRACE_ENDPOINT_RXD_REJECT_SEQ_MISMATCH(ep)               TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd reject seq mismatch\n", ep->id)
#define TRACE_ENDPOINT_RXD_REJECT_CHECKSUM_MISMATCH(ep)          TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd reject checksum mismatch\n", ep->id)
#define TRACE_ENDPOINT_RXD_REJECT_SECURITY_ISSUE(ep)             TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd reject security issue\n", ep->id)
#define TRACE_ENDPOINT_RXD_REJECT_OUT_OF_MEMORY(ep)              TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd reject out of memory\n", ep->id)
#define TRACE_ENDPOINT_RXD_REJECT_FAULT(ep)                      TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: rxd reject fault\n", ep->id)
#define TRACE_ENDPOINT_TXD_DATA_FRAME(ep)                        TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: txd data frame\n", ep->id)
#define TRACE_ENDPOINT_TXD_ACK(ep)                               TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: txd ack\n", ep->id)
#define TRACE_ENDPOINT_TXD_REJECT_DESTINATION_UNREACHABLE(ep)    TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%d: txd reject destination unreachable\n", (ep == NULL) ? -1 : (signed)ep->id)
#define TRACE_ENDPOINT_TXD_REJECT_SEQ_MISMATCH(ep)               TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: txd reject seq mismatch\n", ep->id)
#define TRACE_ENDPOINT_TXD_REJECT_CHECKSUM_MISMATCH(ep)          TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: txd reject checksum mismatch\n", ep->id)
#define TRACE_ENDPOINT_TXD_REJECT_SECURITY_ISSUE(ep)             TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: txd reject security issue\n", ep->id)
#define TRACE_ENDPOINT_TXD_REJECT_OUT_OF_MEMORY(ep)              TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: txd reject out of memory\n", ep->id)
#define TRACE_ENDPOINT_TXD_REJECT_FAULT(ep)                      TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: txd reject fault\n", ep->id)
#define TRACE_ENDPOINT_FRAME_TRANSMIT_SUBMITTED(ep)              TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%d: frame transmit submitted\n", (ep == NULL) ? -1 : (signed) ep->id)
#define TRACE_ENDPOINT_FRAME_TRANSMIT_COMPLETED(ep)              TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%d: frame transmit completed\n", (ep == NULL) ? -1 : (signed) ep->id)
#define TRACE_ENDPOINT_DATA_FRAME_TRANSMIT_COMPLETED(ep)         TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: data frame transmit completed\n", ep->id)
#define TRACE_ENDPOINT_SUPERVISORY_FRAME_TRANSMIT_COMPLETED(ep)  TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: supervisory frame transmit completed\n", ep->id)
#define TRACE_ENDPOINT_RETXD_DATA_FRAME(ep)                      do { EVENT_COUNTER_INC(retxd_data_frame); TRACE_WITH_LEVEL(CPC_TRACE_LEVEL_DEBUG, "Core : Endpoint #%u: re-txd data frame\n", ep->id); } while (0)

#define CRASH() do { signal_crash(); } while (0)

#define WARN(msg, ...)                                                                                                             \
  do {                                                                                                                             \
    TRACE_WARN("In function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__);                \
    if (TRACE_LEVEL_ENABLED(CPC_TRACE_LEVEL_WARN)) {                                                                               \
      fprintf(stderr, "WARNING in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
    }                                                                                                                              \
  } while (0)

#define WARN_ON(cond)                                                                                                      \
  do {                                                                                                                     \
    if (cond) {                                                                                                            \
      TRACE_WARN("On '%s' in function '%s' in file %s at line #%d\n", #cond, __func__, __FILE__, __LINE__);                \
      if (TRACE_LEVEL_ENABLED(CPC_TRACE_LEVEL_WARN)) {                                                                     \
        fprintf(stderr, "WARNING on '%s' in function '%s' in file %s at line #%d\n", #cond, __func__, __FILE__, __LINE__); \
      }                                                                                                                    \
    }                                                                                                                      \
  } while (0)

#define FATAL(msg, ...)                                                                                                          \
  do {                                                                                                                           \
    TRACE_ASSERT("FATAL in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__);      \
    if (TRACE_LEVEL_ENABLED(CPC_TRACE_LEVEL_ERROR)) {                                                                            \
      fprintf(stderr, "FATAL in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
    }                                                                                                                            \
    CRASH();                                                                                                                     \
  } while (0)

#define FATAL_ON(cond)                                                                                                  \
  do {                                                                                                                  \
    if (cond) {                                                                                                         \
      TRACE_ASSERT("FATAL on '%s' in function '%s' in file %s at line #%d\n",#cond, __func__, __FILE__, __LINE__);      \
      if (TRACE_LEVEL_ENABLED(CPC_TRACE_LEVEL_ERROR)) {                                                                 \
        fprintf(stderr, "FATAL on '%s' in function '%s' in file %s at line #%d\n",#cond, __func__, __FILE__, __LINE__); \
      }                                                                                                                 \
      CRASH();                                                                                                          \
    }                                                                                                                   \
  } while (0)

#define FATAL_SYSCALL_ON(cond)                                                                                             \
  do {                                                                                                                     \
    if (cond) {                                                                                                            \
      TRACE_ASSERT("FATAL system call in function '%s' in file %s at line #%d : %m\n", __func__, __FILE__, __LINE__);      \
      if (TRACE_LEVEL_ENABLED(CPC_TRACE_LEVEL_ERROR)) {                                                                    \
        fprintf(stderr, "FATAL system call in function '%s' in file %s at line #%d : %m\n", __func__, __FILE__, __LINE__); \
      }                                                                                                                    \
      CRASH();                                                                                                             \
    }                                                                                                                      \
  } while (0)

// Special version used specifically when the trace file hasn't been opened yet (error while creating it)
#define FATAL_SYSCALL_NO_TRACE_FILE_ON(cond)                                                                               \
  do {                                                                                                                     \
    if (cond) {                                                                                                            \
      if (TRACE_LEVEL_ENABLED(CPC_TRACE_LEVEL_ERROR)) {                                                                    \
        fprintf(stderr, "FATAL system call in function '%s' in file %s at line #%d : %m\n", __func__, __FILE__, __LINE__); \
      }                                                                                                                    \
      CRASH();                                                                                                             \
    }                                                                                                                      \
  } while (0)

#define BUG(msg, ...)                                                                                                          \
  do {                                                                                                                         \
    TRACE_ASSERT("BUG in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__);      \
    if (TRACE_LEVEL_ENABLED(CPC_TRACE_LEVEL_ERROR)) {                                                                          \
      fprintf(stderr, "BUG in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
    }                                                                                                                          \
    CRASH();                                                                                                                   \
  } while (0)

#define BUG_ON(cond)                                                                                                  \
  do {                                                                                                                \
    if (cond) {                                                                                                       \
      TRACE_ASSERT("BUG on '%s' in function '%s' in file %s at line #%d\n",#cond, __func__, __FILE__, __LINE__);      \
      if (TRACE_LEVEL_ENABLED(CPC_TRACE_LEVEL_ERROR)) {                                                               \
        fprintf(stderr, "BUG on '%s' in function '%s' in file %s at line #%d\n",#cond, __func__, __FILE__, __LINE__); \
      }                                                                                                               \
      CRASH();                                                                                                        \
    }                                                                                                                 \
  } while (0)
#endif // LOGGING_H
