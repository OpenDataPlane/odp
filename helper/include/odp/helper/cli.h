/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Nokia
 */

/**
 * @file
 *
 * ODP CLI helper
 */

#ifndef ODPH_CLI_H_
#define ODPH_CLI_H_

#include <stdarg.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup odph_cli ODPH CLI
 * Command line interface
 *
 * @details
 * This API allows control of ODP CLI server, which may be connected to using a
 * telnet client. CLI commands may be used to get information from an ODP
 * instance, for debugging purposes.
 *
 * @{
 */

/**
 * User defined command function type. See odph_cli_register_command().
 *
 * The arguments (argv) are the arguments to the command given in the CLI
 * client. For example, having registered a command with the name "my_command",
 * and given the command "my_command one two" in the CLI client, the user
 * command function would be called with argc = 2, argv[0] = "one" and argv[1] =
 * "two".
 */
typedef void (*odph_cli_user_cmd_func_t)(int argc, char *argv[]);

/** ODP CLI server parameters */
typedef struct {
	/**
	 * A character string containing an IP address. Default is
	 * "127.0.0.1".
	 */
	const char *address;
	/** TCP port. Default is 55555. */
	uint16_t port;
	/** Maximum number of user defined commands. Default is 50. */
	uint32_t max_user_commands;
	/** Hostname to be displayed as the first part of the prompt. */
	const char *hostname;
} odph_cli_param_t;

/**
 * Initialize CLI server params
 *
 * Initialize an odph_cli_param_t to its default values for all
 * fields.
 *
 * @param[out] param Pointer to parameter structure
 */
void odph_cli_param_init(odph_cli_param_t *param);

/**
 * Initialize CLI helper
 *
 * This function initializes the CLI helper. It must be called before
 * odph_cli_register_command() and odph_cli_run().
 *
 * In process mode (ODPH_PROC_MODE), this function must be called before
 * creating the thread which calls odph_cli_run().
 *
 * @param param CLI server parameters to use
 * @retval 0 Success
 * @retval <0 Failure
 */
int odph_cli_init(const odph_cli_param_t *param);

/**
 * Register a user defined command
 *
 * Register a command with a name, function, and an optional help text. The
 * registered command is displayed in the output of the "help" command. When the
 * command is invoked by the CLI client, the registered function is called with
 * the parameters entered by the CLI client user.
 *
 * Command names are case-insensitive. In the CLI client, they are displayed in
 * the case they were registered in, but they may be invoked using any case.
 *
 * This function should be called after odph_cli_init() and before
 * odph_cli_run().
 *
 * @param name Command name (case-insensitive)
 * @param func Command function
 * @param help Help or description for the command. This appears in the output
 *             of the "help" command. May be NULL.
 * @retval 0 Success
 * @retval <0 Failure
 */
int odph_cli_register_command(const char *name, odph_cli_user_cmd_func_t func,
			      const char *help);

/**
 * Run CLI server
 *
 * When executing this function, the CLI is accepting client connections and
 * running commands from a client, if one is connected.
 *
 * This function should be called after odph_cli_init() and after any
 * odph_cli_register_command() calls. After calling this function,
 * odph_cli_stop() must be called before calling this function again.
 *
 * Returns only on a fatal error, or after odph_cli_stop() is called.
 *
 * @retval 0 Success
 * @retval <0 Failure
 */
int odph_cli_run(void);

/**
 * Stop CLI server
 *
 * Stop accepting new client connections and disconnect any connected client.
 *
 * @retval 0 Success
 * @retval <0 Failure
 */
int odph_cli_stop(void);

/**
 * Print to CLI
 *
 * A user defined command may call this function to print to the CLI client.
 * This function should only be called in a user defined command (see
 * odph_cli_register_command()). If called anywhere else, the behavior is
 * undefined.
 *
 * @param fmt printf-style message format
 * @return On success, the number of characters printed or buffered, without
 *         accounting for any line feed conversions. If an error is encountered,
 *         a negative value is returned.
 */
int odph_cli_log(const char *fmt, ...);

/**
 * Print to CLI
 *
 * Similar to odph_cli_log(), except that this one takes its arguments as
 * a va_list.
 *
 * @param fmt printf-style message format
 * @param in_args variadic arguments
 * @return On success, the number of characters printed or buffered, without
 *         accounting for any line feed conversions. If an error is encountered,
 *         a negative value is returned.
 */
int odph_cli_log_va(const char *fmt, va_list in_args);

/**
 * Terminate CLI helper
 *
 * Free any resources allocated by the CLI helper.
 *
 * @retval 0 Success
 * @retval <0 Failure
 */
int odph_cli_term(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
