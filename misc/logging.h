/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Logging Interface
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

#ifndef LOGGING_H
#define LOGGING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

void logging_init(void);

void init_file_logging();

void logging_kill(void);

void trace(const bool force_stdout, const char* string, ...);

void trace_no_timestamp(const char* string, ...);

void trace_frame(const char* string, const void* buffer, size_t len);

#ifdef COMPILE_LTTNG
#include <lttng/tracef.h>
#define LTTNG_TRACE(string, ...)  tracef(string, ##__VA_ARGS__)
#else
#define LTTNG_TRACE(string, ...) (void)0
#endif

#define TRACE(string, ...)                    do { LTTNG_TRACE(string, ##__VA_ARGS__); trace(false, string, ##__VA_ARGS__); } while (0)

#define TRACE_FORCE_STDOUT(string, ...)       do { LTTNG_TRACE(string, ##__VA_ARGS__); trace(true, string, ##__VA_ARGS__); } while (0)

#define PRINT_INFO(string, ...)       TRACE_FORCE_STDOUT("Info : "  string "\n", ##__VA_ARGS__)

#define TRACE_DRIVER(string, ...)     TRACE("Driver : "  string "\n", ##__VA_ARGS__)

#define TRACE_CORE(string, ...)       TRACE("Core : "  string "\n", ##__VA_ARGS__)

#define TRACE_SECURITY(string, ...)   TRACE("Security : "  string "\n", ##__VA_ARGS__)

#define TRACE_SERVER(string, ...)     TRACE("Server : "  string "\n", ##__VA_ARGS__)

#define TRACE_SYSTEM(string, ...)     TRACE("System : "  string "\n", ##__VA_ARGS__)

#define TRACE_RESET(string, ...)      TRACE("Reset Sequence : "  string "\n", ##__VA_ARGS__)

#define TRACE_XMODEM(string, ...)     TRACE("XMODEM : "  string "\n", ##__VA_ARGS__)

#define TRACE_EZSP_SPI(string, ...)   TRACE("EZSPI-SPI : "  string "\n", ##__VA_ARGS__)

#define trace_lib(string, ...)        TRACE("Lib : "  string "\n", ##__VA_ARGS__)

#define TRACE_ASSERT(string, ...)     TRACE_FORCE_STDOUT("*** ASSERT *** : " string, ##__VA_ARGS__)

#define TRACE_FRAME(string, buffer, length) trace_frame(string, buffer, length)

#define TRACE_SERVER_RXD_FRAME(buffer, len)                 TRACE_FRAME("Server : rxd frame : ", buffer, len)

#define TRACE_SERVER_TXD_FRAME(buffer, len)                 TRACE_FRAME("Server : txd frame : ", buffer, len)

#define TRACE_CORE_OPEN_ENDPOINT(ep)                      TRACE_CORE("open ep #%u", ep->id)

#define TRACE_CORE_CLOSE_ENDPOINT(ep)                     TRACE_CORE("close ep #%u", ep->id)

#define TRACE_CORE_RXD_FRAME(buffer, len)                 TRACE_FRAME("Core : rxd frame : ", buffer, len)

#define TRACE_CORE_RXD_VALID_FRAME()                      TRACE_CORE("rxd frame with valid header checksum")

#define TRACE_CORE_RXD_DATA_FRAME_DROPPED()               TRACE_CORE("rxd data frame dropped")

#define TRACE_CORE_TXD_REJECT_DESTINATION_UNREACHABLE()   TRACE_CORE("txd reject destination unreachable")

#define TRACE_CORE_TXD_REJECT_ERROR_FAULT()               TRACE_CORE("txd reject error fault")

#define TRACE_CORE_DRIVER_READ_ERROR()                    TRACE_CORE("driver read error")

#define TRACE_CORE_DRIVER_PACKET_DROPPED()                TRACE_CORE("driver packed dropped")

#define TRACE_CORE_INVALID_HEADER_CHECKSUM()              TRACE_CORE("invalid header checksum")

#define TRACE_CORE_TXD_TRANSMIT_COMPLETED()               TRACE_CORE("txd transmit completed")

#define TRACE_ENDPOINT_RXD_FRAME(ep)                      TRACE_CORE("Endpoint #%u: rxd frame", ep->id)

#define TRACE_ENDPOINT_RXD_DATA_FRAME(ep)                 TRACE_CORE("Endpoint #%u: rxd data frame", ep->id)

#define TRACE_ENDPOINT_RXD_DATA_FRAME_QUEUED(ep)          TRACE_CORE("Endpoint #%u: rxd data frame queued", ep->id)

#define TRACE_ENDPOINT_RXD_DATA_FRAME_DROPPED(ep)         TRACE_CORE("Endpoint #%u: rxd data frame dropped", ep->id)

#define TRACE_ENDPOINT_RXD_SUPERVISORY_FRAME(ep)          TRACE_CORE("Endpoint #%u: rxd supervisory frame", ep->id)

#define TRACE_ENDPOINT_RXD_SUPERVISORY_PROCESSED(ep)      TRACE_CORE("Endpoint #%u: rxd supervisory processed", ep->id)

#define TRACE_ENDPOINT_RXD_SUPERVISORY_DROPPED(ep)        TRACE_CORE("Endpoint #%u: rxd supervisory dropped", ep->id)

#define TRACE_ENDPOINT_RXD_UNNUMBERED_FRAME(ep)           TRACE_CORE("Endpoint #%u: rxd unnumbered frame", ep->id)

#define TRACE_ENDPOINT_RXD_UNNUMBERED_DROPPED(ep, reason) TRACE_CORE("Endpoint #%d: unnumbered frame dropped : %s", ((ep == NULL) ? -1 : (signed) ep->id), reason)

#define TRACE_ENDPOINT_RXD_UNNUMBERED_PROCESSED(ep)       TRACE_CORE("Endpoint #%u: unnumbered frame processed", ep->id)

#define TRACE_ENDPOINT_RXD_DUPLICATE_DATA_FRAME(ep)       TRACE_CORE("Endpoint #%u: rxd duplicate data frame", ep->id)

#define TRACE_ENDPOINT_RXD_ACK(ep)                        TRACE_CORE("Endpoint #%u: rxd ack", ep->id)

#define TRACE_ENDPOINT_RXD_REJECT_DESTINATION_UNREACHABLE(ep)  TRACE_CORE("Endpoint #%u: rxd reject destination unreachable", ep->id)

#define TRACE_ENDPOINT_RXD_REJECT_SEQ_MISMATCH(ep)        TRACE_CORE(" Endpoint #%u: rxd reject seq mismatch", ep->id)

#define TRACE_ENDPOINT_RXD_REJECT_CHECSUM_MISMATCH(ep)    TRACE_CORE("Endpoint #%u: rxd reject checksum mismatch", ep->id)

#define TRACE_ENDPOINT_RXD_REJECT_SECURITY_ISSUE(ep)      TRACE_CORE("Endpoint #%u: rxd reject security issue", ep->id)

#define TRACE_ENDPOINT_RXD_REJECT_OUT_OF_MEMORY(ep)       TRACE_CORE("Endpoint #%u: rxd reject out of memory", ep->id)

#define TRACE_ENDPOINT_RXD_REJECT_FAULT(ep)               TRACE_CORE("Endpoint #%u: rxd reject fault", ep->id)

#define TRACE_ENDPOINT_TXD_DATA_FRAME(ep)                 TRACE_CORE("Endpoint #%u: txd data frame", ep->id)

#define TRACE_ENDPOINT_TXD_ACK(ep)                        TRACE_CORE("Endpoint #%u: txd ack", ep->id)

#define TRACE_ENDPOINT_TXD_REJECT_DESTINATION_UNREACHABLE(ep) TRACE_CORE("Endpoint #%d: txd reject destination unreachable", (ep == NULL) ? -1 : (signed)ep->id)

#define TRACE_ENDPOINT_TXD_REJECT_SEQ_MISMATCH(ep)        TRACE_CORE("Endpoint #%u: txd reject seq mismatch", ep->id)

#define TRACE_ENDPOINT_TXD_REJECT_CHECKSUM_MISMATCH(ep)   TRACE_CORE("Endpoint #%u: txd reject checksum mismatch", ep->id)

#define TRACE_ENDPOINT_TXD_REJECT_SECURITY_ISSUE(ep)      TRACE_CORE("Endpoint #%u: txd reject security issue", ep->id)

#define TRACE_ENDPOINT_TXD_REJECT_OUT_OF_MEMORY(ep)       TRACE_CORE("Endpoint #%u: txd reject out of memory", ep->id)

#define TRACE_ENDPOINT_TXD_REJECT_FAULT(ep)               TRACE_CORE("Endpoint #%u: txd reject fault", ep->id)

#define TRACE_ENDPOINT_RETXD_DATA_FRAME(ep)               TRACE_CORE("Endpoint #%u: re-txd data frame", ep->id)

#define TRACE_ENDPOINT_FRAME_TRANSMIT_SUBMITTED(ep)       TRACE_CORE("Endpoint #%d: frame transmit submitted", (ep == NULL) ? -1 : (signed) ep->id)

#define TRACE_ENDPOINT_FRAME_TRANSMIT_COMPLETED(ep)       TRACE_CORE("Endpoint #%d: frame transmit completed", (ep == NULL) ? -1 : (signed) ep->id)

#define TRACE_ENDPOINT_DATA_FRAME_TRANSMIT_COMPLETED(ep)  TRACE_CORE("Endpoint #%u: data frame transmit completed", ep->id)

#define TRACE_ENDPOINT_SUPERVISORY_FRAME_TRANSMIT_COMPLETED(ep)  TRACE_CORE("Endpoint #%u: supervisory frame transmit completed", ep->id)

#define TRACE_DRIVER_RXD_FRAME(buffer, len)               TRACE_FRAME("Driver : rxd frame : ", buffer, len)

#define OUT_FILE stderr

__attribute__((noreturn)) void cancel_all_threads(int status);

#define CRASH() do { cancel_all_threads(EXIT_FAILURE); } while (0)

#define WARN(msg, ...)                                                                                                             \
  do {                                                                                                                             \
    TRACE_ASSERT("WARNING in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__);      \
    fprintf(OUT_FILE, "WARNING in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
  } while (0)

#define WARN_ON(cond) ({                                                                                                     \
    int __ret = !!(cond);                                                                                                    \
    if (__ret) {                                                                                                             \
      TRACE_ASSERT("WARNING on '%s' in function '%s' in file %s at line #%d\n", #cond, __func__, __FILE__, __LINE__);        \
      fprintf(OUT_FILE, "WARNING on '%s' in function '%s' in file %s at line #%d\n", #cond, __func__, __FILE__, __LINE__); } \
    __ret;                                                                                                                   \
  })

#define FATAL(msg, ...)                                                                                                          \
  do {                                                                                                                           \
    TRACE_ASSERT("FATAL in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__);      \
    fprintf(OUT_FILE, "FATAL in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
    CRASH();                                                                                                                     \
  } while (0)

#define FATAL_ON(cond)                                                                                                   \
  do {                                                                                                                   \
    if (cond) {                                                                                                          \
      TRACE_ASSERT("FATAL on '%s' in function '%s' in file %s  at line #%d\n",#cond, __func__, __FILE__, __LINE__);      \
      fprintf(OUT_FILE, "FATAL on '%s' in function '%s' in file %s  at line #%d\n",#cond, __func__, __FILE__, __LINE__); \
      CRASH();                                                                                                           \
    }                                                                                                                    \
  } while (0)

#define FATAL_SYSCALL_ON(cond)                                                                                             \
  do {                                                                                                                     \
    if (cond) {                                                                                                            \
      TRACE_ASSERT("FATAL system call in function '%s' in file %s at line #%d : %m\n", __func__, __FILE__, __LINE__);      \
      fprintf(OUT_FILE, "FATAL system call in function '%s' in file %s at line #%d : %m\n", __func__, __FILE__, __LINE__); \
      CRASH();                                                                                                             \
    }                                                                                                                      \
  } while (0)

/* Special version used specifically when the trace file hasn't been opened yet (error while creating it) */
#define FATAL_SYSCALL_NO_TRACE_FILE_ON(cond)                                                                               \
  do {                                                                                                                     \
    if (cond) {                                                                                                            \
      fprintf(OUT_FILE, "FATAL system call in function '%s' in file %s at line #%d : %m\n", __func__, __FILE__, __LINE__); \
      CRASH();                                                                                                             \
    }                                                                                                                      \
  } while (0)

#define BUG(msg, ...)                                                                                                          \
  do {                                                                                                                         \
    TRACE_ASSERT("BUG in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__);      \
    fprintf(OUT_FILE, "BUG in function '%s' in file %s at line #%d : " msg "\n", __func__, __FILE__, __LINE__, ##__VA_ARGS__); \
    CRASH();                                                                                                                   \
  } while (0)

#define BUG_ON(cond)                                                                                                  \
  do {                                                                                                                \
    if (cond) {                                                                                                       \
      TRACE_ASSERT("BUG on '%s' in function '%s' in file %s at line #%d\n",#cond, __func__, __FILE__, __LINE__);      \
      fprintf(OUT_FILE, "BUG on '%s' in function '%s' in file %s at line #%d\n",#cond, __func__, __FILE__, __LINE__); \
      CRASH();                                                                                                        \
    }                                                                                                                 \
  } while (0)
#endif //TRACING_H
