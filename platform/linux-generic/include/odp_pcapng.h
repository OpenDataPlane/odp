/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PCAPNG_H_
#define ODP_PCAPNG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/packet.h>
#include <odp_packet_io_internal.h>

#include <stdint.h>

int _odp_pcapng_start(pktio_entry_t *entry);
void _odp_pcapng_stop(pktio_entry_t *entry);
int _odp_pcapng_write_pkts(pktio_entry_t *entry, int qidx,
			   const odp_packet_t packets[], int num);

#ifdef __cplusplus
}
#endif

#endif /* ODP_PCAPNG_H_ */
