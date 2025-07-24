/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2025 Nokia
 */

#ifndef PKTIO_COMMON_H
#define PKTIO_COMMON_H

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <stdio.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Print pktio link info
 *
 * @param pktio        Pktio handle
 * @param pktio_name   Pktio name
 */
static void pktio_common_print_link_info(odp_pktio_t pktio, const char *pktio_name)
{
	odp_pktio_link_info_t info;

	if (odp_pktio_link_info(pktio, &info)) {
		ODPH_ERR("Error (%s): Printing pktio link info not possible, "
			 "information retrieval failed.\n",
			 pktio_name);
		return;
	}

	printf("pktio: %s\n", pktio_name);
	printf("  autoneg       %s\n",
	       (info.autoneg == ODP_PKTIO_LINK_AUTONEG_ON ? "on" :
	       (info.autoneg == ODP_PKTIO_LINK_AUTONEG_OFF ? "off" : "unknown")));
	printf("  duplex        %s\n",
	       (info.duplex == ODP_PKTIO_LINK_DUPLEX_HALF ? "half" :
	       (info.duplex == ODP_PKTIO_LINK_DUPLEX_FULL ? "full" : "unknown")));
	printf("  media         %s\n", info.media);
	printf("  pause_rx      %s\n",
	       (info.pause_rx == ODP_PKTIO_LINK_PAUSE_ON ? "on" :
	       (info.pause_rx == ODP_PKTIO_LINK_PAUSE_OFF ? "off" : "unknown")));
	printf("  pause_tx      %s\n",
	       (info.pause_tx == ODP_PKTIO_LINK_PAUSE_ON ? "on" :
	       (info.pause_tx == ODP_PKTIO_LINK_PAUSE_OFF ? "off" : "unknown")));
	printf("  speed(Mbit/s) %" PRIu32 "\n\n", info.speed);
}

/**
 * Print multiple pktio link infos.
 * Same as pktio_common_print_link_info() but takes arrays of pktio handles and names
 * and prints info for each link.
 *
 * @param pktios        Pktio handles
 * @param pktio_names   Pktio names
 * @param num_pktio     Number of pktio handles and names
 */
static void pktio_common_print_link_info_multi(const odp_pktio_t pktios[],
					       const char *pktio_names[],
					       uint32_t num_pktio)
{
	for (uint32_t i = 0; i < num_pktio; i++)
		pktio_common_print_link_info(pktios[i], pktio_names[i]);
}

/**
 * Wait for pktio links to be up and return status.
 * Wait time is applied once across the entire array of pktios.
 *
 * @param pktios        Pktio handles
 * @param pktio_names   Pktio names
 * @param num_pktio     Number of pktio handles and names
 * @param wait_sec      Seconds to wait for all links to be up
 *
 * @retval 0 on success
 * @retval -1 on failure
 */
static int pktio_common_check_link_status_wait(const odp_pktio_t pktios[],
					       const char *pktio_names[],
					       uint32_t num_pktio,
					       uint32_t wait_sec)
{
	odp_pktio_t pktio;
	const char *name;
	int link_status;
	uint32_t link_wait = 0; /**< Centiseconds waited */
	int ret = 0;

	for (uint32_t i = 0; i < num_pktio; i++) {
		while (1) {
			pktio = pktios[i];
			name = pktio_names[i];
			link_status = odp_pktio_link_status(pktio);

			if (link_status == ODP_PKTIO_LINK_STATUS_UP)
				break;

			link_wait++;

			if (link_wait > wait_sec * 100) {
				if (link_status == ODP_PKTIO_LINK_STATUS_UNKNOWN) {
					printf("Warning (%s): Link status unknown after wait time.\n",
					       name);
					break;
				}

				ODPH_ERR("Error: (%s): Pktio link down after wait time.\n",
					 name);
				ret = -1;
				break;
			}

			odp_time_wait_ns(ODP_TIME_MSEC_IN_NS * 10); /* Wait 10 ms = 1 cs */
		}
	}

	return ret;
}

#ifdef __cplusplus
}
#endif

#endif
