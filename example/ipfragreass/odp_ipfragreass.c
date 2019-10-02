/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_ipfragreass.c  ODP IPv4 lock-free fragmentation and reassembly
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include <odp/helper/odph_api.h>

#include "odp_ipfragreass_fragment.h"
#include "odp_ipfragreass_reassemble.h"
#include "odp_ipfragreass_helpers.h"

#define NUM_PACKETS 200   /**< Number of packets to fragment/reassemble */
#define MAX_WORKERS 32    /**< Maximum number of worker threads */
#define FRAGLISTS   16384 /**< Hash map size for reassembly */

#define MIN_MF_FRAG_SIZE  576  /**< Minimum fragment size */
#define MAX_PKT_LEN	  8192 /**< Maximum packet size */
#define MAX_FRAGS_PER_PKT 6    /**< Maximum number of fragments per packet */

/**
 * Derived parameters for packet storage (inc. pool configuration)
 */
#define POOL_MIN_SEG_LEN IP_HDR_LEN_MIN
#define POOL_UAREA_SIZE	 sizeof(struct packet)
#define MAX_FRAGS	 (MAX_FRAGS_PER_PKT * NUM_PACKETS)

/** Output queue for fragmentation, input queue for reassembly */
static odp_queue_t fragments;

/** Output queue for reassembly, input queue for validation */
static odp_queue_t reassembled_pkts;

/** Number of packets reassembled thus far */
static odp_atomic_u32_t packets_reassembled;

/** Number of fragments processed per thread in reassembly (for printing) */
static struct ODP_ALIGNED_CACHE {
	uint32_t frags;
} thread_stats[MAX_WORKERS];

/** Shared hash map structure for reassembly */
static union fraglist *fraglists;

/** Barrier for synchronising reassembly worker threads */
static odp_barrier_t barrier;

/**
 * Initialise the base structures required for execution of this application
 *
 * @param[out] instance		ODP instance handle to initialise
 * @param[out] fragment_pool	Output for fragment pool creation
 * @param[out] shm		Output for reassembly shared memory creation
 * @param[out] cpumask		Output for worker threads CPU mask
 * @param[out] num_workers	Output for number of worker threads
 */
static void init(odp_instance_t *instance, odp_pool_t *fragment_pool,
		 odp_shm_t *shm, odp_cpumask_t *cpumask, int *num_workers)
{
	unsigned int seed = time(NULL);
	int i;
	odp_pool_param_t pool_params;
	odp_queue_param_t frag_queue_params;
	odp_queue_param_t reass_queue_params;
	char cpumask_str[ODP_CPUMASK_STR_SIZE];

	srand(seed);
	printf("= Seed: %d\n", seed);
	printf("= MTU: %d\n", MTU);

	/* ODP initialisation */
	if (odp_init_global(instance, NULL, NULL)) {
		fprintf(stderr, "ERROR: ODP global init failed.\n");
		exit(1);
	}
	if (odp_init_local(*instance, ODP_THREAD_CONTROL)) {
		fprintf(stderr, "ERROR: ODP local init failed.\n");
		exit(1);
	}

	/* Create a pool for packet storage */
	odp_pool_param_init(&pool_params);
	pool_params.pkt.seg_len    = POOL_MIN_SEG_LEN;
	pool_params.pkt.len	   = MAX_PKT_LEN;
	pool_params.pkt.num	   = 2 * MAX_FRAGS + MAX_WORKERS;
	pool_params.pkt.uarea_size = POOL_UAREA_SIZE;
	pool_params.type	   = ODP_POOL_PACKET;
	*fragment_pool = odp_pool_create("packet pool", &pool_params);
	if (*fragment_pool == ODP_POOL_INVALID) {
		fprintf(stderr, "ERROR: packet pool create failed.\n");
		exit(1);
	}

	/* Reserve (and initialise) shared memory for reassembly fraglists */
	*shm = odp_shm_reserve("fraglists", FRAGLISTS * sizeof(union fraglist),
			       ODP_CACHE_LINE_SIZE, 0);
	if (*shm == ODP_SHM_INVALID) {
		fprintf(stderr, "ERROR: odp_shm_reserve\n");
		exit(1);
	}
	fraglists = odp_shm_addr(*shm);
	if (fraglists == NULL) {
		fprintf(stderr, "ERROR: odp_shm_addr\n");
		exit(1);
	}
	for (i = 0; i < FRAGLISTS; ++i)
		init_fraglist(&fraglists[i]);

	/* Create a queue for holding fragments */
	odp_queue_param_init(&frag_queue_params);
	frag_queue_params.type = ODP_QUEUE_TYPE_PLAIN;
	frag_queue_params.enq_mode = ODP_QUEUE_OP_MT_UNSAFE;
	fragments = odp_queue_create("fragments", &frag_queue_params);
	if (fragments == ODP_QUEUE_INVALID) {
		fprintf(stderr, "ERROR: odp_queue_create\n");
		exit(1);
	}

	/* Create a queue for holding reassembled packets */
	odp_queue_param_init(&reass_queue_params);
	reass_queue_params.type = ODP_QUEUE_TYPE_PLAIN;
	reass_queue_params.deq_mode = ODP_QUEUE_OP_MT_UNSAFE;
	reassembled_pkts = odp_queue_create("reassembled packets",
					    &reass_queue_params);
	if (reassembled_pkts == ODP_QUEUE_INVALID) {
		fprintf(stderr, "ERROR: odp_queue_create\n");
		exit(1);
	}

	/* Set up worker threads */
	*num_workers = odp_cpumask_default_worker(cpumask, *num_workers);
	odp_barrier_init(&barrier, *num_workers + 1);
	odp_cpumask_to_str(cpumask, cpumask_str, sizeof(cpumask_str));
	printf("= Workers: %d\n", *num_workers);
	printf("= CPU Mask: %s (first CPU: %d)\n\n", cpumask_str,
	       odp_cpumask_first(cpumask));
}

/**
 * Reassembly worker thread function
 *
 * Repeatedly dequeues input fragments, validating them and then passing them
 * to the reassembly procedure "reassemble_ipv4_packets". When a packet has
 * been reassembled, it is added to the output queue, and when NUM_PACKETS
 * packets have been completed the function returns. Thread 0 additionally
 * executes the garbage collection procedure to clean up stale fragments.
 *
 * @param arg The thread number of this worker (masquerading as a pointer)
 *
 * @return Always returns zero
 */
static int run_worker(void *arg ODP_UNUSED)
{
	int threadno = odp_thread_id() - 1;
	int iterations = 0;
	odp_event_t ev;

	odp_barrier_wait(&barrier);
	while (odp_atomic_load_u32(&packets_reassembled) < NUM_PACKETS) {
		odp_packet_t pkt;
		odp_time_t timestamp;
		odph_ipv4hdr_t *hdr;
		struct packet *fragment;
		int reassembled;

		ev = odp_queue_deq(fragments);
		if (ev == ODP_EVENT_INVALID)
			break;
		assert(odp_event_type(ev) == ODP_EVENT_PACKET);
		++thread_stats[threadno].frags;

		pkt = odp_packet_from_event(ev);
		hdr = odp_packet_data(pkt);
		fragment = odp_packet_user_area(pkt);
		timestamp = odp_time_global();
		assert(fragment != NULL);
		assert(odp_packet_len(pkt) == ipv4hdr_payload_len(*hdr)
					      + ipv4hdr_ihl(*hdr));
		assert(!ipv4hdr_more_fragments(*hdr) ||
		       (odp_packet_len(pkt) >= MIN_MF_FRAG_SIZE &&
				(odp_packet_len(pkt)
				 - ipv4hdr_ihl(*hdr)) % 8 == 0));
		assert(odp_packet_len(pkt) <= MAX_PKT_LEN);
		fragment->handle    = pkt;
		fragment->prev      = NULL;
		fragment->arrival.t = odp_time_to_ns(timestamp) / TS_RES_NS;

		reassembled = reassemble_ipv4_packets(fraglists, FRAGLISTS,
						      fragment, 1,
						      reassembled_pkts);
		if (reassembled > 0)
			odp_atomic_add_u32(&packets_reassembled, reassembled);

		/*
		 * Perform garbage collection of stale fragments every 50
		 * iterations. (In real applications, use a timer!)
		 */
		if (threadno == 0 && iterations++ > 50) {
			iterations = 0;
			garbage_collect_fraglists(fraglists, FRAGLISTS,
						  reassembled_pkts, 0);
		}
	}

	while ((ev = odp_queue_deq(fragments)) != ODP_EVENT_INVALID) {
		assert(odp_event_type(ev) == ODP_EVENT_PACKET);
		odp_packet_free(odp_packet_from_event(ev));
	}

	return 0;
}

/**
 * ODP fragmentation and reassembly example main function
 */
int main(void)
{
	odp_instance_t instance;
	odp_pool_t fragment_pool;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	odph_odpthread_t threads[MAX_WORKERS];
	odph_odpthread_params_t thread_params;
	odp_packet_t dequeued_pkts[NUM_PACKETS];
	odp_event_t ev;
	odp_u16be_t ip_id = 0;
	odp_packet_t orig_pkts[NUM_PACKETS];
	odp_packet_t fragment_buffer[MAX_FRAGS];
	int total_fragments = 0;
	int i;
	int num_workers = MAX_WORKERS;
	int reassembled;

	memset(&threads, 0, sizeof(threads));
	init(&instance, &fragment_pool, &shm, &cpumask, &num_workers);

	/* Packet generation & fragmentation */
	printf("\n= Fragmenting %d packets...\n", NUM_PACKETS);
	for (i = 0; i < NUM_PACKETS; ++i) {
		odp_packet_t packet;
		int num_fragments;

		packet = pack_udp_ipv4_packet(fragment_pool, ip_id++,
					      MAX_PKT_LEN,
					      MTU + IP_HDR_LEN_MAX + 1);
		if (packet == ODP_PACKET_INVALID) {
			fprintf(stderr, "ERROR: pack_udp_ipv4_packet\n");
			return 1;
		}

		orig_pkts[i] = odp_packet_copy(packet, fragment_pool);
		if (orig_pkts[i] == ODP_PACKET_INVALID) {
			fprintf(stderr, "ERROR: odp_packet_copy\n");
			return 1;
		}

		if (fragment_ipv4_packet(packet,
					 &fragment_buffer[total_fragments],
					 &num_fragments)) {
			fprintf(stderr, "ERROR: fragment_ipv4_packet\n");
			return 1;
		}

		total_fragments += num_fragments;
	}

	/* Shuffle the fragments around so they aren't necessarily in order */
	printf("\n= Shuffling %d fragments...\n", total_fragments);
	shuffle(fragment_buffer, total_fragments);

	/* Insert the fragments into a queue for consumption */
	for (i = 0; i < total_fragments; ++i) {
		ev = odp_packet_to_event(fragment_buffer[i]);

		if (odp_queue_enq(fragments, ev) < 0) {
			fprintf(stderr, "ERROR: odp_queue_enq\n");
			return 1;
		}
	}

	/* Spawn the worker threads for reassembly */
	memset(&thread_params, 0, sizeof(thread_params));
	thread_params.start    = run_worker;
	thread_params.arg      = 0;
	thread_params.thr_type = ODP_THREAD_WORKER;
	thread_params.instance = instance;
	odph_odpthreads_create(threads, &cpumask, &thread_params);

	/* Go! */
	printf("\n= Starting reassembly...\n");
	odp_barrier_wait(&barrier);

	/* Wait for all threads to complete and output statistics */
	odph_odpthreads_join(threads);
	for (i = 0; i < num_workers; ++i)
		printf("=== Thread %02d processed %3d fragments\n", i,
		       thread_stats[i].frags);

	/* Dequeue the reassembled packets */
	for (reassembled = 0; (ev = odp_queue_deq(reassembled_pkts)) !=
	     ODP_EVENT_INVALID; ++reassembled) {
		assert(reassembled < NUM_PACKETS);
		assert(odp_event_type(ev) == ODP_EVENT_PACKET);
		dequeued_pkts[reassembled] = odp_packet_from_event(ev);
	}

	/* Check reassembled packets against the originals */
	printf("\n= Checking reassembled packets...\n");
	for (i = 0; i < reassembled; ++i) {
		int j = -1;
		int k;
		odp_packet_t packet = dequeued_pkts[i];
		uint32_t len = odp_packet_len(packet);
		odph_ipv4hdr_t hdr;
		odph_ipv4hdr_t reassembled_hdr;

		reassembled_hdr = *(odph_ipv4hdr_t *)odp_packet_data(packet);
		for (k = 0; k < reassembled; ++k) {
			hdr = *(odph_ipv4hdr_t *)odp_packet_data(orig_pkts[k]);
			if (hdr.src_addr == reassembled_hdr.src_addr &&
			    hdr.dst_addr == reassembled_hdr.dst_addr &&
			    hdr.id	 == reassembled_hdr.id &&
			    hdr.proto	 == reassembled_hdr.proto) {
				assert(j < 0);
				j = k;
			}
		}
		assert(j >= 0);

		assert(odp_packet_is_valid(packet));
		assert(len == odp_packet_len(orig_pkts[j]));
		assert(!packet_memcmp(orig_pkts[j], packet, 0, 0, len));
	}
	printf("=== Successfully reassembled %d of %d packets\n", reassembled,
	       NUM_PACKETS);
	assert(reassembled == NUM_PACKETS);
	printf("\n= Complete!\n");

	/* Free packets */
	for (i = 0; i < reassembled; ++i)
		odp_packet_free(dequeued_pkts[i]);
	for (i = 0; i < NUM_PACKETS; ++i)
		odp_packet_free(orig_pkts[i]);
	garbage_collect_fraglists(fraglists, FRAGLISTS, reassembled_pkts, 1);

	/* ODP cleanup and termination */
	assert(!odp_queue_destroy(fragments));
	assert(!odp_queue_destroy(reassembled_pkts));
	assert(!odp_shm_free(shm));
	if (odp_pool_destroy(fragment_pool)) {
		fprintf(stderr,
			"ERROR: fragment_pool destruction failed\n");
		return 1;
	}
	if (odp_term_local()) {
		fprintf(stderr, "ERROR: odp_term_local\n");
		return 1;
	}
	if (odp_term_global(instance)) {
		fprintf(stderr, "ERROR: odp_term_global\n");
		return 1;
	}

	return 0;
}
