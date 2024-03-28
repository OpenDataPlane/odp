/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#include <odp_api.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "odp_ipfragreass_reassemble.h"
#include "odp_ipfragreass_helpers.h"

#define ROT(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

/**
 * Check whether two packets have the same flow (src/dst/id/proto)
 *
 * @param current The first packet to compare
 * @param frag    The second packet to compare
 *
 * @return true if the flows match, false otherwise
 */
static inline odp_bool_t equal_flow(struct packet *current, struct packet *frag)
{
	odph_ipv4hdr_t *curr_h = odp_packet_data(current->handle);
	odph_ipv4hdr_t *frag_h = odp_packet_data(frag->handle);

	return (memcmp(&curr_h->src_addr, &frag_h->src_addr,
		       sizeof(curr_h->src_addr) + sizeof(curr_h->dst_addr))
			      == 0 &&
		curr_h->id    == frag_h->id &&
		curr_h->proto == frag_h->proto);
}

/**
 * Check whether one packet has a "later" flow than another
 *
 * @param current The first packet to compare
 * @param frag    The second packet to compare
 *
 * @return true if the first packet's flow is later, false otherwise
 */
static inline odp_bool_t later_flow(struct packet *current, struct packet *frag)
{
	odph_ipv4hdr_t *curr_h = odp_packet_data(current->handle);
	odph_ipv4hdr_t *frag_h = odp_packet_data(frag->handle);

	return (memcmp(&curr_h->src_addr, &frag_h->src_addr,
		       sizeof(curr_h->src_addr) + sizeof(curr_h->dst_addr))
			      > 0 ||
		curr_h->id    > frag_h->id ||
		curr_h->proto > frag_h->proto);
}

/**
 * Find the earliest of two fraglist timestamps, considering a "now" timestamp
 *
 * @param a   The first timestamp
 * @param b   The second timestamp
 * @param now A timestamp indication of the time "now"
 *
 * @return The earliest of the first and second timestamps
 */
static inline struct flts earliest(struct flts a, struct flts b,
				   struct flts now)
{
	struct flts result;
	struct flts elapsed_a;
	struct flts elapsed_b;

	now.t += TS_NOW_TOLERANCE;
	elapsed_a.t = now.t - a.t;
	elapsed_b.t = now.t - b.t;
	result.t = now.t - max(elapsed_a.t, elapsed_b.t);
	return result;
}

/**
 * Hash the flow information within an IPv4 header
 *
 * @param hdr A pointer to the header to hash
 *
 * @return A hash of the src/dst/id/proto information in the header
 */
static inline uint32_t hash(odph_ipv4hdr_t *hdr)
{
	uint32_t a = hdr->src_addr;
	uint32_t b = hdr->dst_addr;
	uint32_t c = (uint32_t)hdr->id << 16 | hdr->proto;

	/* A degenerate 3x32-bit Jenkins hash */
	c ^= b;
	c -= ROT(b, 14);
	a ^= c;
	a -= ROT(c, 11);
	b ^= a;
	b -= ROT(a, 25);
	c ^= b;
	c -= ROT(b, 16);
	a ^= c;
	a -= ROT(c,  4);
	b ^= a;
	b -= ROT(a, 14);
	c ^= b;
	c -= ROT(b, 24);
	return c;
}

/**
 * Check whether one fragment is "later" than another, considering a timestamp
 * of "now"
 *
 * This definition of "later" relies firstly on flow, then on the endpoint of
 * the fragment, then on the fragment offset, then on arrival time.
 *
 * @param a   The first fragment to compare
 * @param b   The second fragment to compare
 * @param now A timestamp indication of the time "now"
 *
 * @return true if the first fragment is "later", false otherwise
 */
static inline odp_bool_t later_fragment(struct packet *a, struct packet *b,
					struct flts now)
{
	odph_ipv4hdr_t hdr_a = *(odph_ipv4hdr_t *)odp_packet_data(a->handle);
	odph_ipv4hdr_t hdr_b = *(odph_ipv4hdr_t *)odp_packet_data(b->handle);
	uint32_t offset_a = ipv4hdr_fragment_offset_oct(hdr_a);
	uint32_t offset_b = ipv4hdr_fragment_offset_oct(hdr_b);
	uint32_t payload_len_a = ipv4hdr_payload_len(hdr_a);
	uint32_t payload_len_b = ipv4hdr_payload_len(hdr_b);
	uint32_t endpoint_a = OCTS_TO_BYTES(offset_a) + payload_len_a;
	uint32_t endpoint_b = OCTS_TO_BYTES(offset_b) + payload_len_b;

	if (later_flow(a, b)) {
		return 1;
	} else if (equal_flow(a, b)) {
		if (endpoint_a > endpoint_b) {
			return 1;
		} else if (endpoint_a == endpoint_b) {
			if (offset_a < offset_b) {
				return 1;
			} else if (offset_a == offset_b) {
				return b->arrival.t == earliest(a->arrival,
								b->arrival,
								now).t;
			}
		}
	}

	return 0;
}

/**
 * Attempt to extract a whole packet from a list of sorted fragments
 *
 * If a complete packet is formed, its tail pointer is returned, and the tail
 * pointer for the remaining packets is written out to remaining_packets.
 *
 * @param[in]  tail		 The tail of the list of fragments to parse
 * @param[out] remaining_packets The pointer to any remaining packets
 * @param[out] made_changes	 Whether any changes were made to the fragments
 *
 * @return The tail pointer of any reassembled packet, or NULL otherwise
 */
static struct packet *extract_complete_packet(struct packet *tail,
					      struct packet **remaining_packets,
					      int *made_changes)
{
	/*
	 * Iterate through the flows in this fragment list (until a packet is
	 * reassembled).
	 */
	 while (tail) {
		/*
		 * Work backwards through the fragments in a single flow,
		 * attempting to glue together a whole packet. Upon finding a
		 * discontinuity, break out of the loop for this flow and try
		 * the next (if there is one).
		 */
		struct packet *current = tail;
		odph_ipv4hdr_t tail_hdr;
		uint16_t final_frag_offset;

		tail_hdr = *(odph_ipv4hdr_t *)odp_packet_data(tail->handle);
		final_frag_offset = ipv4hdr_fragment_offset_oct(tail_hdr);
		while (current) {
			odph_ipv4hdr_t curr_hdr;
			uint16_t curr_offset_oct;
			odp_bool_t final_fragment;
			struct packet *prev;
			void *tmp;
			odph_ipv4hdr_t prev_hdr;
			uint16_t prev_off_oct;
			uint16_t prev_oct;

			tmp = odp_packet_data(current->handle);
			curr_hdr = *(odph_ipv4hdr_t *)tmp;
			curr_offset_oct = ipv4hdr_fragment_offset_oct(curr_hdr);
			final_fragment = (curr_offset_oct == final_frag_offset);

			/*
			 * If the final fragment in the chain has "More
			 * Fragments" set, it's not the final packet of the
			 * datagram as a whole.
			 */
			if (final_fragment && ipv4hdr_more_fragments(curr_hdr))
				break;

			/*
			 * If this is the first fragment in a chain, we may have
			 * completed the reassembly of a whole packet.
			 */
			prev = prev_packet(*current);
			if (prev == NULL || !equal_flow(current, prev)) {
				if (curr_offset_oct)
					break;

				/*
				 * Extract the complete packet from the list of
				 * remaining packets
				 */
				if (remaining_packets)
					*remaining_packets = prev;
				set_prev_packet(current, NULL);
				if (made_changes)
					*made_changes = 1;
				return tail;
			}

			/*
			 * Fragments should be consistent with those previously
			 * processed
			 */
			tmp = odp_packet_data(prev->handle);
			prev_hdr = *(odph_ipv4hdr_t *)tmp;
			prev_off_oct = ipv4hdr_fragment_offset_oct(prev_hdr);
			prev_oct = BYTES_TO_OCTS(ipv4hdr_payload_len(prev_hdr));
			if (curr_offset_oct != prev_off_oct + prev_oct) {
				if (prev_off_oct + prev_oct < curr_offset_oct) {
					/*
					 * If there's no overlap, this is just a
					 * regular discontinuity
					 */
					break;
				}

				/*
				 * Fragment duplication or overlap has occurred!
				 * We don't handle such occurrences in this
				 * simple example application.
				 */
				assert(0);
				break;
			}

			current = prev;
		}

		/*
		 * Since we haven't had any luck finding a whole packet within
		 * this flow, let's try to look at other flows in this fraglist
		 * (if there are any others).
		 */
		if (!current) {
			tail = NULL;
			break;
		}

		while (prev_packet(*current) &&
		       equal_flow(current, prev_packet(*current))) {
			current = prev_packet(*current);
		}
		tail = prev_packet(*current);
		remaining_packets = prev_packet_ptr(current);
	}

	return NULL;
}

/*
 * Glue together a list of fragments sorted by fragment offset, writing the
 * result to an output queue
 *
 * @param tail The tail pointer to the list of fragments to reassemble
 * @param out  The output queue to write the result to
 *
 * @return 0 on success, -1 otherwise
 */
static int send_packet(struct packet *tail, odp_queue_t out)
{
	struct packet result = *tail;
	struct packet *current = prev_packet(result);
	odph_ipv4hdr_t *header;
	uint32_t length;

	/*
	 * Reassemble the complete packet (working backwards from the last
	 * fragment)
	 */
	while (current && equal_flow(current, &result)) {
		struct packet new_result = *current;
		int concat_success, trunc_success;

		current = prev_packet(new_result);
		header = odp_packet_data(result.handle);
		trunc_success = odp_packet_trunc_head(&result.handle, ipv4hdr_ihl(*header),
						      NULL, NULL);
		if (trunc_success < 0) {
			fprintf(stderr, "ERROR: odp_packet_trunc_head\n");
			return -1;
		}

		concat_success = odp_packet_concat(&new_result.handle,
						   result.handle);
		if (concat_success < 0) {
			fprintf(stderr, "ERROR: odp_packet_concat\n");
			return -1;
		}
		result = new_result;
	}

	/* Fix the header */
	header = odp_packet_data(result.handle);
	length = odp_packet_len(result.handle);
	assert(length >= IP_HDR_LEN_MIN || length <= UINT16_MAX);
	header->tot_len = odp_cpu_to_be_16(length);
	ipv4hdr_set_more_fragments(header, 0);
	ipv4hdr_set_fragment_offset_oct(header, 0);
	header->chksum = 0;
	odph_ipv4_csum_update(result.handle);

	assert(odp_queue_enq(out, odp_packet_to_event(result.handle)) >= 0);
	return 0;
}

/**
 * Sort a fraglist using the "later_fragment" function
 *
 * @param fl  A pointer to the fraglist to sort
 * @param now A timestamp indication of the time "now"
 */
static void sort_fraglist(union fraglist *fl, struct flts now)
{
	struct packet *to_insert = fl->tail;

	fl->tail = NULL;
	while (to_insert) {
		struct packet *to_insert_next = prev_packet(*to_insert);

		if (fl->tail == NULL ||
		    later_fragment(to_insert, fl->tail, now)) {
			set_prev_packet(to_insert, fl->tail);
			fl->tail = to_insert;
		} else {
			struct packet *current = fl->tail;

			while (prev_packet(*current) &&
			       later_fragment(prev_packet(*current), to_insert,
					      now)) {
				current = prev_packet(*current);
			}
			set_prev_packet(to_insert, prev_packet(*current));
			set_prev_packet(current, to_insert);
		}
		to_insert = to_insert_next;
	}
}

/**
 * Add a thread local fraglist to a shared fraglist
 *
 * @param fl		Pointer to the shared fraglist to add "frags" to
 * @param frags		The thread local fraglist to add to "fl"
 * @param frags_head	Pointer to the head fragment of "frags"
 * @param now		A timestamp indication of the time "now"
 * @param out		The queue to which reassembled packets should be written
 * @param dont_assemble	Whether reassembly should be attempted by default
 *
 * @return The number of packets reassembled and sent to the output queue
 */
static int add_fraglist_to_fraglist(odp_atomic_u128_t *fl, union fraglist frags,
				    struct packet *frags_head, struct flts now,
				    odp_queue_t out, odp_bool_t dont_assemble)
{
	int reassembled = 0;

	/*
	 * We may need to recursively call this function a number of times,
	 * keeping count of the total number of packets reassembled. Sadly,
	 * tail call optimisation doesn't seem to be working very well, so
	 * we're using good ol' fashioned GOTOs instead.
	 */
redo:;
	union fraglist oldfl;
	union fraglist newfl;
	union fraglist nullfl;
	struct flts oldfl_earliest;
	struct flts frags_earliest;

	oldfl.raw = odp_atomic_load_u128(fl);

	/*
	 * If we're updating a non-empty fraglist, we should always attempt
	 * reassembly!
	 */
	if (oldfl.tail != NULL)
		dont_assemble = 0;

	/* Insert the new fragment(s) to the tail of the fraglist */
	set_prev_packet(frags_head, oldfl.tail);
	newfl.tail = frags.tail;

	/*
	 * Update the fraglist variables (accumulating the length of the
	 * received pieces into "part_len", and updating the perceived 'true'
	 * length of the whole packet along with the timestamp of the earliest
	 * fragment in this list).
	 */
	oldfl_earliest.t = oldfl.earliest;
	frags_earliest.t = frags.earliest;
	newfl.part_len  = min(IP_OCTET_MAX, oldfl.part_len + frags.part_len);
	newfl.whole_len = min(oldfl.whole_len, frags.whole_len);
	newfl.earliest  = (oldfl.tail == NULL ? frags.earliest
					      : earliest(oldfl_earliest,
							 frags_earliest,
							 now).t);

	/*
	 * Check if it looks like we have all the fragments for a whole packet
	 * yet. If not, just write out our changes and move on.
	 */
	if (newfl.part_len < newfl.whole_len || dont_assemble) {
		if (!odp_atomic_cas_rel_u128(fl, &oldfl.raw, newfl.raw)) {
			/* Failed to add this fragment? Try again. */
			set_prev_packet(frags_head, NULL);
			goto redo;
		}
		return reassembled;
	}

	/*
	 * It /appears/ that we have all the fragments for a packet. Things are
	 * not always as they appear, however, particularly in the case of a
	 * hash map collision where part_len and whole_len may be incorrect
	 * (and, hence, must be verified).
	 *
	 * Take exclusive ownership over this fraglist while we attempt
	 * reassembly. If we're truly done with it, then this releases the slot,
	 * otherwise we'll update the slot with our changes later.
	 */
	init_fraglist(&nullfl);
	if (!odp_atomic_cas_acq_u128(fl, &oldfl.raw, nullfl.raw)) {
		/* Failed to take this fraglist? Try again. */
		set_prev_packet(frags_head, NULL);
		goto redo;
	}

	/*
	 * Find any complete packets within the fraglist, cut them out of the
	 * list, and send them to the output queue. Note that there may be
	 * several complete packets, as we may have added multiple new fragments
	 * into the fraglist.
	 */
	struct packet *remaining_packets;
	struct packet *complete_datagram;
	int fraglist_changed = 0;
	int call_changed_fraglist = 0;
	union fraglist update;

	sort_fraglist(&newfl, now);
	remaining_packets = newfl.tail;
	dont_assemble = 1;
	while ((complete_datagram =
		extract_complete_packet(remaining_packets, &remaining_packets,
					&call_changed_fraglist)) ||
		call_changed_fraglist) {
		fraglist_changed = 1;
		if (complete_datagram) {
			assert(!send_packet(complete_datagram, out));
			++reassembled;
			dont_assemble = 0;
		}
		call_changed_fraglist = 0;
	}

	/* No remaining fragments in this fraglist? We're done. */
	if (!remaining_packets)
		return reassembled;

	/*
	 * If there are still fragments in this fraglist, we have changes to
	 * write back.
	 *
	 * Note that we may have to reassemble more packets, as adding the
	 * fragments this thread has exclusive access to into the shared
	 * fraglist may entail new packets being completed. Thus, we have to
	 * repeat this whole add_fraglist_to_fraglist process with the remaining
	 * fragments.
	 */
	update.tail      = remaining_packets;
	update.part_len  = newfl.part_len;
	update.whole_len = newfl.whole_len;
	update.earliest  = newfl.earliest;

	/*
	 * We've cut fragments from the fragment list chain, and so should
	 * recalculate the part_len, whole_len, and earliest variables before
	 * writing out our changes.
	 */
	if (fraglist_changed) {
		struct packet *current = remaining_packets;

		update.earliest = now.t;
		while (current) {
			odph_ipv4hdr_t *h;
			uint16_t part_oct;
			uint16_t whole_oct;
			struct flts update_earliest;

			update_earliest.t = update.earliest;
			h = odp_packet_data(current->handle);
			part_oct = ipv4hdr_payload_len_oct(*h);
			whole_oct = ipv4hdr_reass_payload_len_oct(*h);
			update.part_len = min(IP_OCTET_MAX,
					      update.part_len + part_oct);
			update.whole_len = min(update.whole_len, whole_oct);
			update.earliest = earliest(update_earliest,
						   current->arrival, now).t;
			frags_head = current;
			current = prev_packet(*current);
		}
		frags = update;
		goto redo;
	}

	frags = update;
	frags_head = frags.tail;
	while (prev_packet(*frags_head))
		frags_head = prev_packet(*frags_head);
	goto redo;
}

/**
 * Add a single fragment to a shared fraglist
 *
 * @param fl Pointer to the shared fraglist to add "frag" to
 * @param frag Pointer to the fragment to add to "fl"
 * @param frag_payload_len The payload length of "frag" in octets
 * @param frag_reass_payload_len The estimated reassembled payload length of
 *                               "frag" in octets
 * @param out The queue to which reassembled packets should be written
 *
 * @return The number of packets reassembled and sent to the output
 */
static int add_frag_to_fraglist(odp_atomic_u128_t *fl, struct packet *frag,
				uint16_t frag_payload_len,
				uint16_t frag_reass_payload_len,
				odp_queue_t out)
{
	union fraglist frags;

	frags.tail = frag;
	frags.part_len = frag_payload_len;
	frags.whole_len = frag_reass_payload_len;
	frags.earliest = frag->arrival.t;

	return add_fraglist_to_fraglist(fl, frags, frags.tail, frag->arrival,
					out, 0);
}

/**
 * Remove the stale flows from a shared fraglist this thread has exclusive
 * access over
 *
 * @param fl	   Pointer to the shared fraglist to clean stale flows from
 * @param oldfl	   The value of the fraglist before we took exclusive access
 * @param time_now A timestamp indication of the time "now"
 * @param out	   The queue to which reassembled packets should be written
 * @param force	   Whether all flows in the fraglist should be considered stale
 */
static void remove_stale_flows(odp_atomic_u128_t *fl, union fraglist oldfl,
			       struct flts timestamp_now, odp_queue_t out,
			       odp_bool_t force)
{
	union fraglist newfl = oldfl;
	struct packet *current;
	struct packet *current_tail;
	struct packet *remaining_frags_head;
	struct flts flow_earliest;

	/*
	 * Sort the fraglist so we can step through its fragments flow-by-flow
	 */
	sort_fraglist(&newfl, timestamp_now);

	/* Remove stale flows from the fraglist */
	current = newfl.tail;
	current_tail = newfl.tail;
	remaining_frags_head = NULL;
	flow_earliest = current->arrival;
	newfl.earliest = timestamp_now.t;
	while (current) {
		struct packet *prev = prev_packet(*current);

		/*
		 * If this is the first fragment in a chain, we can make the
		 * decision on whether this flow should be kept or discarded
		 */
		if (prev == NULL || !equal_flow(current, prev)) {
			struct flts elapsed;
			uint64_t elapsed_ns;

			elapsed.t = timestamp_now.t - flow_earliest.t;
			elapsed_ns = (elapsed.t * TS_RES_NS);
			if ((elapsed_ns >= FLOW_TIMEOUT_NS &&
			     elapsed.t + TS_NOW_TOLERANCE >=
			     TS_NOW_TOLERANCE) || force) {
				struct packet *to_free = current_tail;

				while (to_free != prev) {
					struct packet *next;

					next = prev_packet(*to_free);
					odp_packet_free(to_free->handle);
					to_free = next;
				}

				if (remaining_frags_head)
					set_prev_packet(remaining_frags_head,
							prev);
				else
					newfl.tail = prev;
			} else {
				odph_ipv4hdr_t *h;
				uint16_t part_oct;
				uint16_t whole_oct;
				struct flts newfl_earliest;

				newfl_earliest.t = newfl.earliest;
				remaining_frags_head = current;
				h = odp_packet_data(current->handle);
				part_oct = ipv4hdr_payload_len_oct(*h);
				whole_oct = ipv4hdr_reass_payload_len_oct(*h);
				newfl.part_len = min(IP_OCTET_MAX,
						     newfl.part_len + part_oct);
				newfl.whole_len = min(newfl.whole_len,
						      whole_oct);
				newfl.earliest = earliest(newfl_earliest,
							  flow_earliest,
							  timestamp_now).t;
			}

			current_tail = prev;
			flow_earliest.t = EARLIEST_MAX;
		} else {
			flow_earliest = earliest(flow_earliest,
						 current->arrival,
						 timestamp_now);
		}

		current = prev;
	}

	/*
	 * If there are any remaining fragments, write them back into the
	 * fraglist
	 */
	if (remaining_frags_head)
		add_fraglist_to_fraglist(fl, newfl, remaining_frags_head,
					 timestamp_now, out, 0);
}

/**
 * Clean up any stale flows within a fraglist
 *
 * @param fl	   Pointer to the shared fraglist to clean stale flows from
 * @param out	   The queue to which reassembled packets should be written
 * @param force	   Whether all flows in the fraglist should be considered stale
 */
static void garbage_collect_fraglist(odp_atomic_u128_t *fl, odp_queue_t out,
				     odp_bool_t force)
{
	uint64_t time_now;
	struct flts timestamp_now;
	struct flts elapsed;
	uint64_t elapsed_ns;
	union fraglist oldfl;
	odp_bool_t success = 1;

	do {
		time_now = odp_time_to_ns(odp_time_global());
		timestamp_now.t = time_now / TS_RES_NS;

		oldfl.raw = odp_atomic_load_u128(fl);

		elapsed.t = timestamp_now.t - oldfl.earliest;

		if (oldfl.tail == NULL ||
		    elapsed.t + TS_NOW_TOLERANCE < TS_NOW_TOLERANCE)
			return;

		elapsed_ns = (elapsed.t * TS_RES_NS);
		assert(force || elapsed_ns <= 86400000000000);
		if (elapsed_ns >= FLOW_TIMEOUT_NS || force) {
			union fraglist nullfl;

			init_fraglist(&nullfl);
			success = odp_atomic_cas_acq_u128(fl, &oldfl.raw,
							  nullfl.raw);
			if (success)
				remove_stale_flows(fl, oldfl, timestamp_now,
						   out, force);
		}
	} while (!success);
}

int reassemble_ipv4_packets(odp_atomic_u128_t *fraglists, int num_fraglists,
			    struct packet *fragments, int num_fragments,
			    odp_queue_t out)
{
	int i;
	int packets_reassembled = 0;

	for (i = 0; i < num_fragments; ++i) {
		struct packet frag;
		odph_ipv4hdr_t *hdr;
		uint16_t frag_payload_len;
		uint16_t frag_reass_payload_len;
		uint32_t key;
		odp_atomic_u128_t *fl;
		int status;

		frag = fragments[i];
		hdr = odp_packet_data(frag.handle);
		frag_payload_len = ipv4hdr_payload_len_oct(*hdr);
		frag_reass_payload_len = ipv4hdr_reass_payload_len_oct(*hdr);

		/*
		 * Find the appropriate hash map bucket for fragments in this
		 * flow. In the case of collisions, fragments for multiple flows
		 * are simply stored in the same list.
		 */
		key = hash(hdr);
		fl = &fraglists[key % num_fraglists];

		status = add_frag_to_fraglist(fl, &fragments[i],
					      frag_payload_len,
					      frag_reass_payload_len, out);
		if (status < 0) {
			fprintf(stderr,
				"ERROR: failed to add fragment to fraglist\n");
			return -1;
		}
		packets_reassembled += status;
	}

	return packets_reassembled;
}

void garbage_collect_fraglists(odp_atomic_u128_t *fraglists, int num_fraglists,
			       odp_queue_t out, odp_bool_t destroy_all)
{
	int i;

	for (i = 0; i < num_fraglists; ++i)
		garbage_collect_fraglist(&fraglists[i], out, destroy_all);
}
