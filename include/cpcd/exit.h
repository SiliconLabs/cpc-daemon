/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - Exit Daemon
 *******************************************************************************
 * # License
 * <b>Copyright 2024 Silicon Laboratories Inc. www.silabs.com</b>
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

#ifndef EXIT_H
#define EXIT_H

/***************************************************************************//**
 * Initializes daemon exit mechanisms.
 ******************************************************************************/
void exit_init(pthread_t main_thread_id);

/***************************************************************************//**
 * Blocks until exit signal. exit_daemon() may be called once this returns.
 ******************************************************************************/
void wait_crash_or_graceful_exit(void);

/***************************************************************************//**
 * Cleanup all threads and exit daemon.
 ******************************************************************************/
__attribute__((noreturn)) void software_graceful_exit(void);

/***************************************************************************//**
 * Signal threads that daemon has crashed.
 ******************************************************************************/
__attribute__((noreturn)) void signal_crash(void);

/***************************************************************************//**
 * Signal child threads that the daemon is exiting.
 ******************************************************************************/
__attribute__((noreturn)) void exit_daemon(void);

#endif // EXIT_H
