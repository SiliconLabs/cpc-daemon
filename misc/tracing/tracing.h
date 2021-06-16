/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Tracing Interface
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

#ifndef TRACING_H
#define TRACING_H

void tracing_init(void);

void trace(const char* string, ...);

void trace_frame(const char* string, const void* buffer, size_t len);

#define TRACE_MAIN(string, ...)       trace("Main : "  string "\n", ##__VA_ARGS__)

#define TRACE_DRIVER(string, ...)     trace("Driver : "  string "\n", ##__VA_ARGS__)

#define TRACE_CORE(string, ...)       trace("Core : "  string "\n", ##__VA_ARGS__)

#define TRACE_SERVER(string, ...)     trace("Server : "  string "\n", ##__VA_ARGS__)

#define TRACE_SYSTEM(string, ...)     trace("System : "  string "\n", ##__VA_ARGS__)

#define TRACE_RESET(string, ...)      trace("Reset Sequence : "  string "\n", ##__VA_ARGS__)

#define trace_lib(string, ...)        trace("Lib : "  string "\n", ##__VA_ARGS__)

#define TRACE_ASSERT(string, ...)     trace("Assert : " string "\n", ##__VA_ARGS__)

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

#endif //TRACING_H
