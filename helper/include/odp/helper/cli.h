/* Copyright (c) 2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP CLI helper API
 *
 * This API allows control of ODP CLI server, which may be connected to
 * using a telnet client. CLI commands may be used to get information
 * from an ODP instance, for debugging purposes.
 *
 * Many CLI commands output the information to the console, or wherever
 * ODP logs have been directed to in global init.
 */

#ifndef ODPH_CLI_H_
#define ODPH_CLI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>
#include <odp/helper/ip.h>
#include <stdint.h>

/**
 * @addtogroup odph_cli ODPH CLI
 * @{
 */

/** ODP CLI server parameters */
typedef struct {
	/**
	 * A character string containing an IP address. Default is
	 * "127.0.0.1".
	 */
	const char *address;
	/** TCP port. Default is 55555. */
	uint16_t port;
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
 * Start CLI server
 *
 * Upon successful return from this function, the CLI server will be
 * accepting client connections. This function spawns a new thread of
 * type ODP_THREAD_CONTROL using odp_cpumask_default_control().
 *
 * @param instance ODP instance
 * @param param CLI server parameters to use
 * @retval 0 Success
 * @retval <0 Failure
 */
int odph_cli_start(const odp_instance_t instance,
		   const odph_cli_param_t *param);

/**
 * Stop CLI server
 *
 * Stop accepting new client connections and disconnect currently
 * connected client. This function terminates the control thread
 * created in odph_cli_start().
 *
 * @retval 0 Success
 * @retval <0 Failure
 */
int odph_cli_stop(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
