/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <odp_api.h>
#include <instrum_common.h>
#include <pktio_direct.h>
#include <store.h>

static int (*instr_odp_pktout_send)(odp_pktout_queue_t queue,
				    const odp_packet_t packets[],
				    int num);

static int (*instr_odp_pktin_recv_tmo)(odp_pktin_queue_t queue,
				       odp_packet_t packets[],
				       int num, uint64_t wait);

int instr_odppktio_direct_init(void)
{
	INSTR_FUNCTION(odp_pktout_send);

	if (!instr_odp_pktout_send) {
		printf("odp_pktout_send: Not Found\n");
		return -1;
	}

	INSTR_FUNCTION(odp_pktin_recv_tmo);

	if (!instr_odp_pktin_recv_tmo) {
		printf("odp_pktin_recv_tmo: Not Found\n");
		return -1;
	}

	return 0;
}

int odp_pktout_send(odp_pktout_queue_t queue, const odp_packet_t packets[],
		    int num)
{
	int ret;

	STORE_SAMPLE_INIT;

	STORE_SAMPLE_START;
	ret = (*instr_odp_pktout_send)(queue, packets, num);
	STORE_SAMPLE_END;

	return ret;
}

int odp_pktin_recv_tmo(odp_pktin_queue_t queue, odp_packet_t packets[],
		       int num, uint64_t wait)
{
	int ret;

	STORE_SAMPLE_INIT;

	STORE_SAMPLE_START;
	ret = (*instr_odp_pktin_recv_tmo)(queue, packets, num, wait);
	STORE_SAMPLE_END;

	return ret;
}

