/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

#ifndef PERF_COMMON_H
#define PERF_COMMON_H

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
 * @param pktio      Pktio handle
 * @param name       Pktio name
 */
static void test_common_print_link_info(odp_pktio_t pktio, const char *name)
{
	odp_pktio_link_info_t info;

	if (odp_pktio_link_info(pktio, &info)) {
		ODPH_ERR("Error (%s): Printing pktio link not possible: "
		"Information retrieval failed.\n", name);
		return;
	}

	printf("pktio: %s\n", name);
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
 * Wait for pktio links to be up and return status
 *
 * @param pktio         Pktio handle
 * @param pktio_name    Pktio name
 * @param wait_sec      Seconds to wait for link to be up
 *
 * @retval 0 on success
 * @retval -1 on failure
 */
static int test_common_check_link_status_wait(odp_pktio_t pktio,
				  const char *pktio_name,
				  uint32_t wait_sec)
{
	uint32_t link_wait = wait_sec * 100; /**< Wait time in centiseconds */
	int link_status = ODP_PKTIO_LINK_STATUS_UNKNOWN;

	while (link_wait--) {
		link_status = odp_pktio_link_status(pktio);

		if (link_status == ODP_PKTIO_LINK_STATUS_UP)
			break;

		odp_time_wait_ns(ODP_TIME_MSEC_IN_NS * 10); /**< Check every 10 ms */
	}

	if (link_status == ODP_PKTIO_LINK_STATUS_DOWN) {
		ODPH_ERR("Error (%s): Link status down after wait time.\n",
			 pktio_name);
		return -1;
	} else if (link_status == ODP_PKTIO_LINK_STATUS_UNKNOWN) {
		printf("Warning (%s): Link status unknown after wait time.\n",
		       pktio_name);
	}

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif
