/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Classification Internal
 * Describes the classification internal Functions
 */

#ifndef __ODP_CLASSIFICATION_INTERNAL_H_
#define __ODP_CLASSIFICATION_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/classification.h>
#include <odp/api/queue.h>
#include <odp_packet_internal.h>
#include <odp/api/packet_io.h>
#include <odp_packet_io_internal.h>
#include <odp_classification_datamodel.h>

/** Classification Internal function **/

/**
@internal

Packet Classifier

Start function for Packet Classifier
This function calls Classifier module internal functions for a given packet and
selects destination queue and packet pool based on selected PMR and CoS.
**/
int cls_classify_packet(pktio_entry_t *entry, const uint8_t *base,
			uint16_t pkt_len, uint32_t seg_len, odp_pool_t *pool,
			odp_packet_hdr_t *pkt_hdr, odp_bool_t parse);

/**
Packet IO classifier init

This function does initialization of classifier object associated with pktio.
This function should be called during pktio initialization.
**/
int pktio_classifier_init(pktio_entry_t *pktio);

#ifdef __cplusplus
}
#endif
#endif
