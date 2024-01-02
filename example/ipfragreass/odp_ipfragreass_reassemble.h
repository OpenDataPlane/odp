/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef ODP_FRAGREASS_PP_REASSEMBLE_H_
#define ODP_FRAGREASS_PP_REASSEMBLE_H_

#include <odp_api.h>
#include <odp/helper/ip.h>

#include "odp_ipfragreass_ip.h"
#include "odp_ipfragreass_helpers.h"

ODP_STATIC_ASSERT(__SIZEOF_POINTER__ <= 8, "ODP_REASS_PTR__SIZE_ERROR");

/**
 * The time in nanoseconds after reception of the earliest fragment that a
 * flow of traffic is considered to be stale
 */
#define FLOW_TIMEOUT_NS 15000000000ULL

/** Convert nanoseconds into a unit for packet.arrival */
#define TS_RES_NS ((uint64_t)1000000)    /**< ns -> 1ms */

/**
 * The maximum value of the packet.arrival field.
 */
#define EARLIEST_MAX UINT32_MAX

/**
 * The time in packet.arrival ticks that indications of the time "now" are
 * permitted to be off by.
 */
#define TS_NOW_TOLERANCE 5000

/**
 * The timestamp format used for fragments. Sadly, this has to be a structure
 * as we may need a bit field.
 */
struct flts {
	uint32_t t;
};

/**
 * Metadata for reassembly, to be stored alongside each fragment
 */
struct packet {
	odp_packet_t handle; /**< The ODP packet handle for this fragment  */
	struct packet *prev; /**< Pointer to the fragment "before" this one */
	struct flts arrival; /**< Arrival timestamp for this fragment */
};

/**
 * A list of IP fragments associated with one or more traffic flows, along with
 * some related data
 *
 * This is used as an atomically-updated hash map bucket in reassembly, and is
 * assumed to be packed with no padding.
 */
union fraglist {
	struct {
		/**
		 * The timestamp of the earliest arriving fragment in this
		 * fraglist
		 */
		uint32_t earliest;

		/**
		 * The sum of the payloads of the fragments in this list
		 *
		 * That is, the size of reassembling all the fragments in this
		 * list into one big packet (minus the header).
		 */
		uint32_t part_len:14;

		/**
		 * The smallest reassembled payload length upper bound from
		 * all fragments in this list
		 *
		 * This is the threshold over which, given the right
		 * circumstances, "part_len" might indicate that we are able
		 * to reassemble a packet.
		 */
		uint32_t whole_len:14;

		/**
		 * The tail of a "reverse" linked list of fragments
		 *
		 * Each fragment element has a "prev" pointer to the element
		 * before it in the list. When used in a multi-threaded
		 * environment, new elements should be inserted atomically by
		 * modifying this tail pointer.
		 */
		struct packet *tail;
	};

	odp_u128_t raw;
};

/**
 * Initialise a fraglist structure
 *
 * @param fl The fraglist to initialise
 */
static inline void init_fraglist(union fraglist *fl)
{
	fl->earliest  = EARLIEST_MAX;
	fl->part_len  = 0;
	fl->whole_len = IP_OCTET_MAX;
	fl->tail      = NULL;
}

/**
 * Get the packet "before" a packet in a linked list
 *
 * @param packet The packet from which the previous should be located
 *
 * @return A pointer to the packet before the input packet (can be NULL)
 */
static inline struct packet *prev_packet(struct packet packet)
{
	return packet.prev;
}

/**
 * Get the address of the pointer to the packet "before" a packet in a linked
 * list
 *
 * @param packet The packet for which the previous pointer should be located
 *
 * @return A pointer to the "prev" packet pointer of the input packet
 */
static inline struct packet **prev_packet_ptr(struct packet *packet)
{
	return &packet->prev;
}

/**
 * Set the packet "before" a packet in a linked list
 *
 * @param packet The packet to set the previous packet from
 * @param prev   The packet to set as being before "packet"
 */
static inline void set_prev_packet(struct packet *packet, struct packet *prev)
{
	packet->prev = prev;
}

/**
 * Attempt packet reassembly with the aid of a number of new fragments
 *
 * Add "num_fragments" fragments to a fraglist hash map (with "num_fraglist"
 * entries), attempting reassembly and writing any successfully reassembled
 * packets out to the "out" queue.
 *
 * @param fraglists	The hash map structure to add the fragments to
 * @param num_fraglists	The number of entries in the hash map
 * @param fragments	Pointer to the fragments to add
 * @param num_fragments	The number of fragments to add
 * @param out		The queue to which reassembled packets should be written
 *
 * @return The number of packets successfully reassembled and written to "out"
 */
int reassemble_ipv4_packets(odp_atomic_u128_t *fraglists, int num_fraglists,
			    struct packet *fragments, int num_fragments,
			    odp_queue_t out);

/**
 * Clean up any stale flows within a fraglist hash map
 *
 * @param fraglists	The hash map structure to clean flows from
 * @param num_fraglists	The number of entries in the hash map
 * @param out		The queue to which reassembled packets should be written
 * @param destroy_all	Whether all encountered flows should be cleaned up
 */
void garbage_collect_fraglists(odp_atomic_u128_t *fraglists, int num_fraglists,
			       odp_queue_t out, odp_bool_t destroy_all);

#endif
