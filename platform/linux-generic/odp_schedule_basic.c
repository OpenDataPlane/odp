/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2019-2025 Nokia
 */

/*
 * Suppress bounds warnings about interior zero length arrays. Such an array
 * is used intentionally in prio_queue_t.
 */
#if __GNUC__ >= 10
#pragma GCC diagnostic ignored "-Wzero-length-bounds"
#endif

#include <odp_posix_extensions.h>

#include <odp/api/schedule.h>
#include <odp_schedule_if.h>
#include <odp/api/align.h>
#include <odp/api/shared_memory.h>
#include <odp_debug_internal.h>
#include <odp/api/thread.h>
#include <odp/api/plat/thread_inlines.h>
#include <odp/api/time.h>
#include <odp/api/plat/time_inlines.h>
#include <odp/api/ticketlock.h>
#include <odp/api/hints.h>
#include <odp/api/cpu.h>
#include <odp/api/thrmask.h>
#include <odp_config_internal.h>
#include <odp/api/sync.h>
#include <odp/api/packet_io.h>
#include <odp_ring_mpmc_rst_u32_internal.h>
#include <odp_timer_internal.h>
#include <odp_queue_basic_internal.h>
#include <odp_libconfig_internal.h>
#include <odp/api/plat/queue_inlines.h>
#include <odp/api/plat/schedule_inline_types.h>
#include <odp_global_data.h>
#include <odp_event_internal.h>
#include <odp_macros_internal.h>
#include <odp_string_internal.h>

#include <string.h>
#include <time.h>
#include <inttypes.h>

/* No synchronization context */
#define NO_SYNC_CONTEXT ODP_SCHED_SYNC_PARALLEL

/* Number of priority levels  */
#define NUM_PRIO 8

/* Group mask (prio_grp_mask) size in bits */
#define GRP_MASK_BITS 64

/* Number of scheduling groups. Maximum value is GRP_MASK_BITS. */
#define NUM_SCHED_GRPS GRP_MASK_BITS

/* Spread balancing frequency. Balance every BALANCE_ROUNDS_M1 + 1 scheduling rounds. */
#define BALANCE_ROUNDS_M1 0xfffff

/* Number of scheduled queue synchronization types */
#define NUM_SCHED_SYNC 3

/* Queue types used as array indices */
ODP_STATIC_ASSERT(ODP_SCHED_SYNC_PARALLEL == 0, "ODP_SCHED_SYNC_PARALLEL_value_changed");
ODP_STATIC_ASSERT(ODP_SCHED_SYNC_ATOMIC == 1, "ODP_SCHED_SYNC_ATOMIC_value_changed");
ODP_STATIC_ASSERT(ODP_SCHED_SYNC_ORDERED == 2, "ODP_SCHED_SYNC_ORDERED_value_changed");

/* Load of a queue */
#define QUEUE_LOAD 256

/* Margin for load balance hysteresis */
#define QUEUE_LOAD_MARGIN 8

/* Ensure that load calculation does not wrap around */
ODP_STATIC_ASSERT((QUEUE_LOAD * CONFIG_MAX_SCHED_QUEUES) < UINT32_MAX, "Load_value_too_large");

/* Maximum priority queue spread */
#define MAX_SPREAD 8

/* Minimum priority queue spread */
#define MIN_SPREAD 1

/* A thread polls a non preferred sched queue every this many polls
 * of the prefer queue. */
#define MAX_PREFER_WEIGHT 127
#define MIN_PREFER_WEIGHT 1
#define MAX_PREFER_RATIO  (MAX_PREFER_WEIGHT + 1)

/* Spread weight table */
#define SPREAD_TBL_SIZE ((MAX_SPREAD - 1) * MAX_PREFER_RATIO)

/* Random data table size */
#define RANDOM_TBL_SIZE 128

/* Maximum number of packet IO interfaces */
#define NUM_PKTIO CONFIG_PKTIO_ENTRIES

/* Maximum pktin index. Needs to fit into 8 bits. */
#define MAX_PKTIN_INDEX 255

/* Maximum priority queue ring size. A ring must be large enough to store all
 * queues in the worst case (all queues are scheduled, have the same priority
 * and no spreading). */
#define MAX_RING_SIZE CONFIG_MAX_SCHED_QUEUES

/* For best performance, the number of queues should be a power of two. */
ODP_STATIC_ASSERT(_ODP_CHECK_IS_POWER2(CONFIG_MAX_SCHED_QUEUES),
		  "Number_of_queues_is_not_power_of_two");

/* Ring size must be power of two, so that mask can be used. */
ODP_STATIC_ASSERT(_ODP_CHECK_IS_POWER2(MAX_RING_SIZE),
		  "Ring_size_is_not_power_of_two");

/* Thread ID is saved into uint16_t variable */
ODP_STATIC_ASSERT(ODP_THREAD_COUNT_MAX < (64 * 1024),
		  "Max_64k_threads_supported");

/* Mask of queues per priority */
typedef uint8_t prio_q_mask_t;

ODP_STATIC_ASSERT((8 * sizeof(prio_q_mask_t)) >= MAX_SPREAD,
		  "prio_q_mask_t_is_too_small");

/* Start of named groups in group mask arrays */
#define SCHED_GROUP_NAMED (ODP_SCHED_GROUP_CONTROL + 1)

/* Limits for burst size configuration */
#define BURST_MAX  255
#define STASH_SIZE CONFIG_BURST_SIZE

/* Ordered stash size */
#define MAX_ORDERED_STASH 512

/* Storage for stashed enqueue operation arguments */
typedef struct {
	_odp_event_hdr_t *event_hdr[QUEUE_MULTI_MAX];
	odp_queue_t queue;
	int num;
} ordered_stash_t;

/* Ordered lock states */
typedef union {
	uint8_t u8[CONFIG_QUEUE_MAX_ORD_LOCKS];
	uint32_t all;
} lock_called_t;

ODP_STATIC_ASSERT(sizeof(lock_called_t) == sizeof(uint32_t),
		  "Lock_called_values_do_not_fit_in_uint32");

/* Shuffled values from 0 to 127 */
static uint8_t sched_random_u8[] = {
	0x5B, 0x56, 0x21, 0x28, 0x77, 0x2C, 0x7E, 0x10,
	0x29, 0x73, 0x39, 0x74, 0x60, 0x2B, 0x2D, 0x3E,
	0x6C, 0x4C, 0x1B, 0x79, 0x14, 0x76, 0x7B, 0x5A,
	0x4F, 0x3B, 0x0B, 0x16, 0x66, 0x0D, 0x05, 0x27,
	0x3F, 0x7F, 0x67, 0x3C, 0x41, 0x6F, 0x4E, 0x7A,
	0x04, 0x26, 0x11, 0x7C, 0x43, 0x38, 0x30, 0x2A,
	0x03, 0x22, 0x17, 0x75, 0x08, 0x71, 0x6D, 0x6B,
	0x0A, 0x4B, 0x52, 0x1D, 0x63, 0x59, 0x1C, 0x50,
	0x15, 0x1A, 0x64, 0x42, 0x47, 0x62, 0x1F, 0x37,
	0x46, 0x5D, 0x19, 0x35, 0x78, 0x68, 0x57, 0x7D,
	0x3A, 0x31, 0x4A, 0x45, 0x09, 0x49, 0x00, 0x01,
	0x65, 0x13, 0x48, 0x70, 0x5E, 0x69, 0x36, 0x58,
	0x1E, 0x5C, 0x23, 0x12, 0x18, 0x25, 0x55, 0x32,
	0x33, 0x61, 0x2F, 0x02, 0x06, 0x53, 0x24, 0x6E,
	0x2E, 0x5F, 0x54, 0x6A, 0x20, 0x07, 0x0F, 0x51,
	0x3D, 0x34, 0x44, 0x0C, 0x4D, 0x40, 0x72, 0x0E
};

ODP_STATIC_ASSERT(sizeof(sched_random_u8) == RANDOM_TBL_SIZE, "Bad_random_table_size");

/* Scheduler local data */
typedef struct ODP_ALIGNED_CACHE {
	uint32_t sched_round;
	uint16_t thr;
	uint8_t  pause;
	uint8_t  sync_ctx;
	uint8_t  balance_on;
	uint16_t balance_start;
	uint16_t spread_round;

	struct {
		uint16_t    num_ev;
		uint16_t    ev_index;
		uint32_t    qi;
		odp_queue_t queue;
		ring_mpmc_rst_u32_t   *ring;
		odp_event_t ev[STASH_SIZE];
	} stash;

	uint64_t grp_mask;
	uint32_t grp_epoch;
	uint16_t num_grp;
	uint8_t grp_idx;
	uint8_t grp[NUM_SCHED_GRPS];
	uint8_t spread_tbl[SPREAD_TBL_SIZE];

	struct {
		/* Source queue index */
		uint32_t src_queue;
		uint64_t ctx; /**< Ordered context id */
		int stash_num; /**< Number of stashed enqueue operations */
		uint8_t in_order; /**< Order status */
		lock_called_t lock_called; /**< States of ordered locks */
		/** Storage for stashed enqueue operations */
		ordered_stash_t stash[MAX_ORDERED_STASH];
	} ordered;

} sched_local_t;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
/* Priority queue */
typedef struct ODP_ALIGNED_CACHE {
	/* Ring header */
	ring_mpmc_rst_u32_t ring;

	/* Ring data: queue indexes */
	uint32_t queue_index[MAX_RING_SIZE]; /* overlaps with ring.data[] */

} prio_queue_t;
#pragma GCC diagnostic pop

/* Order context of a queue */
typedef struct ODP_ALIGNED_CACHE {
	/* Current ordered context id */
	odp_atomic_u64_t ctx ODP_ALIGNED_CACHE;

	/* Next unallocated context id */
	odp_atomic_u64_t next_ctx;

	/* Array of ordered locks */
	odp_atomic_u64_t lock[CONFIG_QUEUE_MAX_ORD_LOCKS];

} order_context_t;

typedef struct {
	struct {
		uint8_t burst_default[NUM_SCHED_SYNC][NUM_PRIO];
		uint8_t burst_max[NUM_SCHED_SYNC][NUM_PRIO];
		uint16_t order_stash_size;
		uint8_t num_spread;
		uint8_t prefer_ratio;
	} config;
	uint32_t         ring_mask;
	uint16_t         max_spread;
	uint8_t          load_balance;
	odp_atomic_u32_t grp_epoch;
	odp_shm_t        shm;
	odp_ticketlock_t mask_lock[NUM_SCHED_GRPS];
	prio_q_mask_t    prio_q_mask[NUM_SCHED_GRPS][NUM_PRIO];

	/* Groups on a priority level that have queues created */
	odp_atomic_u64_t prio_grp_mask[NUM_PRIO];

	struct {
		uint8_t grp;
		/* Inverted prio value (max = 0) vs API (min = 0)*/
		uint8_t prio;
		uint8_t spread;
		uint8_t sync;
		uint8_t order_lock_count;
		uint8_t poll_pktin;
		uint8_t pktio_index;
		uint8_t pktin_index;
	} queue[CONFIG_MAX_SCHED_QUEUES];

	/* Scheduler priority queues */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	prio_queue_t prio_q[NUM_SCHED_GRPS][NUM_PRIO][MAX_SPREAD];
#pragma GCC diagnostic pop
	uint32_t prio_q_count[NUM_SCHED_GRPS][NUM_PRIO][MAX_SPREAD];

	/* Number of queues per group and priority  */
	uint32_t prio_grp_count[NUM_PRIO][NUM_SCHED_GRPS];

	odp_thrmask_t  mask_all;
	odp_ticketlock_t grp_lock;

	struct {
		char           name[ODP_SCHED_GROUP_NAME_LEN];
		odp_thrmask_t  mask;
		uint16_t       spread_thrs[MAX_SPREAD];
		uint8_t        allocated;
		uint8_t        level[NUM_PRIO];
		uint32_t       num_prio;
	} sched_grp[NUM_SCHED_GRPS];

	struct {
		int num_pktin;
	} pktio[NUM_PKTIO];
	odp_ticketlock_t pktio_lock;

	order_context_t order[CONFIG_MAX_SCHED_QUEUES];

	struct {
		uint32_t poll_time;
		uint64_t sleep_time;
	} powersave;

	/* Scheduler interface config options (not used in fast path) */
	schedule_config_t config_if;
	uint32_t max_queues;
	uint32_t num_grps;
	uint32_t num_grp_prios;
	odp_atomic_u32_t next_rand;

} sched_global_t;

/* Check that queue[] variables are large enough */
ODP_STATIC_ASSERT(NUM_SCHED_GRPS  <= GRP_MASK_BITS, "Groups do not fit into group mask");
ODP_STATIC_ASSERT(NUM_PRIO        <= 256, "Prio_does_not_fit_8_bits");
ODP_STATIC_ASSERT(MAX_SPREAD      <= 256, "Spread_does_not_fit_8_bits");
ODP_STATIC_ASSERT(CONFIG_QUEUE_MAX_ORD_LOCKS <= 256,
		  "Ordered_lock_count_does_not_fit_8_bits");
ODP_STATIC_ASSERT(NUM_PKTIO        <= 256, "Pktio_index_does_not_fit_8_bits");

/* Global scheduler context */
static sched_global_t *sched;

/* Thread local scheduler context */
static __thread sched_local_t sched_local;

extern schedule_fn_t _odp_schedule_basic_fn;
static int schedule_ord_enq_multi_no_stash(odp_queue_t dst_queue,
					   void *event_hdr[],
					   int num, int *ret);

static void prio_grp_mask_init(void)
{
	int i;

	for (i = 0; i < NUM_PRIO; i++)
		odp_atomic_init_u64(&sched->prio_grp_mask[i], 0);
}

static inline void prio_grp_mask_set(int prio, int grp)
{
	uint64_t grp_mask = (uint64_t)1 << grp;
	uint64_t mask = odp_atomic_load_u64(&sched->prio_grp_mask[prio]);

	odp_atomic_store_u64(&sched->prio_grp_mask[prio], mask | grp_mask);

	sched->prio_grp_count[prio][grp]++;
}

static inline void prio_grp_mask_clear(int prio, int grp)
{
	uint64_t grp_mask = (uint64_t)1 << grp;
	uint64_t mask = odp_atomic_load_u64(&sched->prio_grp_mask[prio]);

	sched->prio_grp_count[prio][grp]--;

	if (sched->prio_grp_count[prio][grp] == 0)
		odp_atomic_store_u64(&sched->prio_grp_mask[prio], mask &= (~grp_mask));
}

static inline uint64_t prio_grp_mask_check(int prio, uint64_t grp_mask)
{
	return odp_atomic_load_u64(&sched->prio_grp_mask[prio]) & grp_mask;
}

static int read_burst_size_conf(uint8_t out_tbl[], const char *conf_str,
				int min_val, int max_val, int print)
{
	int burst_val[NUM_PRIO];
	const int max_len = 256;
	const int n = max_len - 1;
	char line[max_len];
	int len = 0;

	if (_odp_libconfig_lookup_array(conf_str, burst_val, NUM_PRIO) !=
	    NUM_PRIO) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		return -1;
	}

	char str[strlen(conf_str) + 4];

	snprintf(str, sizeof(str), "%s[]:", conf_str);
	len += snprintf(&line[len], n - len, "  %-38s", str);

	for (int i = 0; i < NUM_PRIO; i++) {
		int val = burst_val[i];

		if (val > max_val || val < min_val) {
			_ODP_ERR("Bad value for %s: %i\n", conf_str, val);
			return -1;
		}
		len += snprintf(&line[len], n - len, " %3i", val);
		if (val > 0)
			out_tbl[i] = val;
	}
	if (print)
		_ODP_PRINT("%s\n", line);

	return 0;
}

static int read_config_file(sched_global_t *sched)
{
	const char *str;
	int val = 0;

	_ODP_PRINT("Scheduler config:\n");

	str = "sched_basic.prio_spread";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	if (val > MAX_SPREAD || val < MIN_SPREAD) {
		_ODP_ERR("Bad value %s = %u [min: %u, max: %u]\n", str, val,
			 MIN_SPREAD, MAX_SPREAD);
		return -1;
	}

	sched->config.num_spread = val;
	_ODP_PRINT("  %s: %i\n", str, val);

	str = "sched_basic.prio_spread_weight";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	if (val > MAX_PREFER_WEIGHT || val < MIN_PREFER_WEIGHT) {
		_ODP_ERR("Bad value %s = %u [min: %u, max: %u]\n", str, val,
			 MIN_PREFER_WEIGHT, MAX_PREFER_WEIGHT);
		return -1;
	}

	sched->config.prefer_ratio = val + 1;
	_ODP_PRINT("  %s: %i\n", str, val);

	str = "sched_basic.load_balance";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	if (val > 1 || val < 0) {
		_ODP_ERR("Bad value %s = %i\n", str, val);
		return -1;
	}
	_ODP_PRINT("  %s: %i\n", str, val);

	sched->load_balance = 1;
	if (val == 0 || sched->config.num_spread == 1)
		sched->load_balance = 0;

	str = "sched_basic.order_stash_size";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	if (val > MAX_ORDERED_STASH || val < 0) {
		_ODP_ERR("Bad value %s = %i [min: 0, max: %u]\n", str, val, MAX_ORDERED_STASH);
		return -1;
	}

	sched->config.order_stash_size = val;
	_ODP_PRINT("  %s: %i\n", str, val);

	/* Initialize default values for all queue types */
	str = "sched_basic.burst_size_default";
	if (read_burst_size_conf(sched->config.burst_default[ODP_SCHED_SYNC_ATOMIC], str, 1,
				 STASH_SIZE, 1) ||
	    read_burst_size_conf(sched->config.burst_default[ODP_SCHED_SYNC_PARALLEL], str, 1,
				 STASH_SIZE, 0) ||
	    read_burst_size_conf(sched->config.burst_default[ODP_SCHED_SYNC_ORDERED], str, 1,
				 STASH_SIZE, 0))
		return -1;

	str = "sched_basic.burst_size_max";
	if (read_burst_size_conf(sched->config.burst_max[ODP_SCHED_SYNC_ATOMIC], str, 1,
				 BURST_MAX, 1) ||
	    read_burst_size_conf(sched->config.burst_max[ODP_SCHED_SYNC_PARALLEL], str, 1,
				 BURST_MAX, 0) ||
	    read_burst_size_conf(sched->config.burst_max[ODP_SCHED_SYNC_ORDERED], str, 1,
				 BURST_MAX, 0))
		return -1;

	if (read_burst_size_conf(sched->config.burst_default[ODP_SCHED_SYNC_ATOMIC],
				 "sched_basic.burst_size_atomic", 0, STASH_SIZE, 1))
		return -1;

	if (read_burst_size_conf(sched->config.burst_max[ODP_SCHED_SYNC_ATOMIC],
				 "sched_basic.burst_size_max_atomic", 0, BURST_MAX, 1))
		return -1;

	if (read_burst_size_conf(sched->config.burst_default[ODP_SCHED_SYNC_PARALLEL],
				 "sched_basic.burst_size_parallel", 0, STASH_SIZE, 1))
		return -1;

	if (read_burst_size_conf(sched->config.burst_max[ODP_SCHED_SYNC_PARALLEL],
				 "sched_basic.burst_size_max_parallel", 0, BURST_MAX, 1))
		return -1;

	if (read_burst_size_conf(sched->config.burst_default[ODP_SCHED_SYNC_ORDERED],
				 "sched_basic.burst_size_ordered", 0, STASH_SIZE, 1))
		return -1;

	if (read_burst_size_conf(sched->config.burst_max[ODP_SCHED_SYNC_ORDERED],
				 "sched_basic.burst_size_max_ordered", 0, BURST_MAX, 1))
		return -1;

	str = "sched_basic.group_enable.all";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	sched->config_if.group_enable.all = val;
	_ODP_PRINT("  %s: %i\n", str, val);

	str = "sched_basic.group_enable.worker";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	sched->config_if.group_enable.worker = val;
	_ODP_PRINT("  %s: %i\n", str, val);

	str = "sched_basic.group_enable.control";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	sched->config_if.group_enable.control = val;
	_ODP_PRINT("  %s: %i\n", str, val);

	str = "sched_basic.powersave.poll_time_nsec";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	sched->powersave.poll_time = _ODP_MAX(0, val);
	_ODP_PRINT("  %s: %i\n", str, val);

	str = "sched_basic.powersave.sleep_time_nsec";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	val = _ODP_MAX(0, val);
	val = _ODP_MIN((int)ODP_TIME_SEC_IN_NS - 1, val);
	sched->powersave.sleep_time = val;
	_ODP_PRINT("  %s: %i\n", str, val);

	_ODP_PRINT("  dynamic load balance: %s\n", sched->load_balance ? "ON" : "OFF");

	_ODP_PRINT("\n");

	return 0;
}

/* Spread from thread or other index */
static inline uint8_t spread_from_index(uint32_t index)
{
	return index % sched->config.num_spread;
}

static void sched_local_init(void)
{
	int i;
	uint8_t spread, prefer_ratio;
	uint8_t num_spread = sched->config.num_spread;
	uint8_t offset = 1;

	memset(&sched_local, 0, sizeof(sched_local_t));

	sched_local.thr         = odp_thread_id();
	sched_local.sync_ctx    = NO_SYNC_CONTEXT;
	sched_local.stash.queue = ODP_QUEUE_INVALID;

	spread = spread_from_index(sched_local.thr);
	prefer_ratio = sched->config.prefer_ratio;

	for (i = 0; i < SPREAD_TBL_SIZE; i++) {
		sched_local.spread_tbl[i] = spread;

		if (num_spread > 1 && (i % prefer_ratio) == 0) {
			sched_local.spread_tbl[i] = spread_from_index(spread + offset);
			offset++;
			if (offset == num_spread)
				offset = 1;
		}
	}
}

static int schedule_init_global(void)
{
	odp_shm_t shm;
	int i, j, grp;
	int prefer_ratio;
	uint32_t ring_size, num_rings;

	_ODP_DBG("Schedule init ... ");

	shm = odp_shm_reserve("_odp_sched_basic_global",
			      sizeof(sched_global_t),
			      ODP_CACHE_LINE_SIZE,
			      0);
	if (shm == ODP_SHM_INVALID) {
		_ODP_ERR("Schedule init: Shm reserve failed.\n");
		return -1;
	}

	sched = odp_shm_addr(shm);
	memset(sched, 0, sizeof(sched_global_t));

	if (read_config_file(sched)) {
		odp_shm_free(shm);
		return -1;
	}

	if (sched->config.order_stash_size == 0)
		_odp_schedule_basic_fn.ord_enq_multi = schedule_ord_enq_multi_no_stash;

	sched->shm = shm;
	prefer_ratio = sched->config.prefer_ratio;

	/* When num_spread == 1, only spread_tbl[0] is used. */
	sched->max_spread = (sched->config.num_spread - 1) * prefer_ratio;

	/* Dynamic load balance may move all queues into a single ring.
	 * Ring size can be smaller with fixed spreading. */
	if (sched->load_balance) {
		ring_size = MAX_RING_SIZE;
		num_rings = 1;
	} else {
		ring_size = MAX_RING_SIZE / sched->config.num_spread;
		num_rings = sched->config.num_spread;
	}

	ring_size = _ODP_ROUNDUP_POWER2_U32(ring_size);
	_ODP_ASSERT(ring_size <= MAX_RING_SIZE);
	sched->ring_mask = ring_size - 1;

	sched->config_if.max_groups = NUM_SCHED_GRPS - SCHED_GROUP_NAMED;
	sched->config_if.max_group_prios = NUM_SCHED_GRPS * NUM_PRIO;
	sched->config_if.max_prios = NUM_PRIO;
	sched->config_if.min_prio = 0;
	sched->config_if.max_prio = NUM_PRIO - 1;
	sched->config_if.def_prio = sched->config_if.max_prio / 2;
	/* Each ring can hold in maximum ring_size-1 queues. Due to ring size round up,
	 * total capacity of rings may be larger than CONFIG_MAX_SCHED_QUEUES. */
	sched->max_queues = sched->ring_mask * num_rings;
	if (sched->max_queues > CONFIG_MAX_SCHED_QUEUES)
		sched->max_queues = CONFIG_MAX_SCHED_QUEUES;

	for (grp = 0; grp < NUM_SCHED_GRPS; grp++) {
		odp_ticketlock_init(&sched->mask_lock[grp]);

		for (i = 0; i < NUM_PRIO; i++) {
			for (j = 0; j < MAX_SPREAD; j++) {
				prio_queue_t *prio_q;

				prio_q = &sched->prio_q[grp][i][j];
				ring_mpmc_rst_u32_init(&prio_q->ring);
			}
		}
	}

	odp_ticketlock_init(&sched->pktio_lock);
	for (i = 0; i < NUM_PKTIO; i++)
		sched->pktio[i].num_pktin = 0;

	odp_ticketlock_init(&sched->grp_lock);
	odp_atomic_init_u32(&sched->grp_epoch, 0);
	odp_atomic_init_u32(&sched->next_rand, 0);

	prio_grp_mask_init();

	for (i = 0; i < NUM_SCHED_GRPS; i++) {
		memset(sched->sched_grp[i].name, 0, ODP_SCHED_GROUP_NAME_LEN);
		odp_thrmask_zero(&sched->sched_grp[i].mask);

		for (j = 0; j < (int)sched->config_if.max_prios; ++j)
			sched->sched_grp[i].level[j] = sched->config_if.min_prio + j;

		sched->sched_grp[i].num_prio = sched->config_if.max_prios;
	}

	sched->sched_grp[ODP_SCHED_GROUP_ALL].allocated = 1;
	sched->sched_grp[ODP_SCHED_GROUP_WORKER].allocated = 1;
	sched->sched_grp[ODP_SCHED_GROUP_CONTROL].allocated = 1;

	_odp_strcpy(sched->sched_grp[ODP_SCHED_GROUP_ALL].name, "__SCHED_GROUP_ALL",
		    ODP_SCHED_GROUP_NAME_LEN);
	_odp_strcpy(sched->sched_grp[ODP_SCHED_GROUP_WORKER].name, "__SCHED_GROUP_WORKER",
		    ODP_SCHED_GROUP_NAME_LEN);
	_odp_strcpy(sched->sched_grp[ODP_SCHED_GROUP_CONTROL].name, "__SCHED_GROUP_CONTROL",
		    ODP_SCHED_GROUP_NAME_LEN);

	odp_thrmask_setall(&sched->mask_all);

	_ODP_DBG("done\n");

	return 0;
}

static int schedule_term_global(void)
{
	int ret = 0;
	int rc = 0;
	int i, j, grp;
	uint32_t ring_mask = sched->ring_mask;

	for (grp = 0; grp < NUM_SCHED_GRPS; grp++) {
		for (i = 0; i < NUM_PRIO; i++) {
			for (j = 0; j < MAX_SPREAD; j++) {
				ring_mpmc_rst_u32_t *ring;
				uint32_t qi;

				ring = &sched->prio_q[grp][i][j].ring;

				while (ring_mpmc_rst_u32_deq(ring, ring_mask, &qi)) {
					odp_event_t events[1];
					int num;

					num = _odp_sched_queue_deq(qi, events, 1, 1);

					if (num > 0)
						_ODP_ERR("Queue not empty\n");
				}
			}
		}
	}

	ret = odp_shm_free(sched->shm);
	if (ret < 0) {
		_ODP_ERR("Shm free failed for odp_scheduler");
		rc = -1;
	}

	return rc;
}

static int schedule_init_local(void)
{
	sched_local_init();
	return 0;
}

static inline void grp_update_mask(int grp, const odp_thrmask_t *new_mask)
{
	odp_thrmask_copy(&sched->sched_grp[grp].mask, new_mask);
	odp_atomic_add_rel_u32(&sched->grp_epoch, 1);
}

static inline int grp_update_tbl(void)
{
	int i;
	int num = 0;
	int thr = sched_local.thr;
	uint64_t mask = 0;

	odp_ticketlock_lock(&sched->grp_lock);

	for (i = 0; i < NUM_SCHED_GRPS; i++) {
		if (sched->sched_grp[i].allocated == 0)
			continue;

		if (odp_thrmask_isset(&sched->sched_grp[i].mask, thr)) {
			sched_local.grp[num] = i;
			num++;
			mask |= (uint64_t)1 << i;
		}
	}

	odp_ticketlock_unlock(&sched->grp_lock);

	sched_local.grp_mask = mask;
	sched_local.grp_idx = 0;
	sched_local.num_grp = num;

	return num;
}

static uint32_t schedule_max_ordered_locks(void)
{
	return CONFIG_QUEUE_MAX_ORD_LOCKS;
}

static int schedule_min_prio(void)
{
	return sched->config_if.min_prio;
}

static int schedule_max_prio(void)
{
	return sched->config_if.max_prio;
}

static int schedule_default_prio(void)
{
	return sched->config_if.def_prio;
}

static int schedule_num_prio(void)
{
	return sched->config_if.max_prios;
}

static inline int prio_level_from_api(int api_prio)
{
	return schedule_max_prio() - api_prio;
}

static inline void dec_queue_count(int grp, int prio, int spr)
{
	odp_ticketlock_lock(&sched->mask_lock[grp]);

	sched->prio_q_count[grp][prio][spr]--;

	/* Clear mask bit only when the last queue is removed */
	if (sched->prio_q_count[grp][prio][spr] == 0)
		sched->prio_q_mask[grp][prio] &= (uint8_t)(~(1 << spr));

	odp_ticketlock_unlock(&sched->mask_lock[grp]);
}

static inline void update_queue_count(int grp, int prio, int old_spr, int new_spr)
{
	odp_ticketlock_lock(&sched->mask_lock[grp]);

	sched->prio_q_mask[grp][prio] |= 1 << new_spr;
	sched->prio_q_count[grp][prio][new_spr]++;

	sched->prio_q_count[grp][prio][old_spr]--;

	if (sched->prio_q_count[grp][prio][old_spr] == 0)
		sched->prio_q_mask[grp][prio] &= (uint8_t)(~(1 << old_spr));

	odp_ticketlock_unlock(&sched->mask_lock[grp]);
}

static uint8_t allocate_spread(int grp, int prio)
{
	uint8_t i, num_min, spr;
	uint32_t num;
	uint32_t min = UINT32_MAX;
	uint8_t num_spread = sched->config.num_spread;
	uint8_t min_spr[num_spread];

	num_min = 1;
	min_spr[0] = 0;

	odp_ticketlock_lock(&sched->mask_lock[grp]);

	/* Find spread(s) with the minimum number of queues */
	for (i = 0; i < num_spread; i++) {
		num = sched->prio_q_count[grp][prio][i];
		if (num < min) {
			min = num;
			min_spr[0] = i;
			num_min = 1;
		} else if (num == min) {
			min_spr[num_min] = i;
			num_min++;
		}
	}

	spr = min_spr[0];

	/* When there are multiple minimum spreads, select one randomly */
	if (num_min > 1) {
		uint32_t next_rand = odp_atomic_fetch_inc_u32(&sched->next_rand);
		uint8_t rand = sched_random_u8[next_rand % RANDOM_TBL_SIZE];

		spr = min_spr[rand % num_min];
	}

	sched->prio_q_mask[grp][prio] |= 1 << spr;
	sched->prio_q_count[grp][prio][spr]++;

	odp_ticketlock_unlock(&sched->mask_lock[grp]);

	return spr;
}

static int check_queue_prio(int prio, int grp)
{
	for (uint32_t i = 0; i < sched->sched_grp[grp].num_prio; i++)
		if (prio == sched->sched_grp[grp].level[i])
			return 1;

	return 0;
}

static int schedule_create_queue(uint32_t queue_index,
				 const odp_schedule_param_t *sched_param)
{
	int i;
	uint8_t spread;
	int grp  = sched_param->group;
	int prio = prio_level_from_api(sched_param->prio);

	if (odp_global_rw->schedule_configured == 0) {
		_ODP_ERR("Scheduler has not been configured\n");
		return -1;
	}

	if (grp < 0 || grp >= NUM_SCHED_GRPS) {
		_ODP_ERR("Bad schedule group %i\n", grp);
		return -1;
	}
	if (!check_queue_prio(sched_param->prio, grp)) {
		_ODP_ERR("Bad priority %i\n", sched_param->prio);
		return -1;
	}
	if (grp == ODP_SCHED_GROUP_ALL && !sched->config_if.group_enable.all) {
		_ODP_ERR("Trying to use disabled ODP_SCHED_GROUP_ALL\n");
		return -1;
	}
	if (grp == ODP_SCHED_GROUP_CONTROL && !sched->config_if.group_enable.control) {
		_ODP_ERR("Trying to use disabled ODP_SCHED_GROUP_CONTROL\n");
		return -1;
	}
	if (grp == ODP_SCHED_GROUP_WORKER && !sched->config_if.group_enable.worker) {
		_ODP_ERR("Trying to use disabled ODP_SCHED_GROUP_WORKER\n");
		return -1;
	}

	odp_ticketlock_lock(&sched->grp_lock);

	if (sched->sched_grp[grp].allocated == 0) {
		odp_ticketlock_unlock(&sched->grp_lock);
		_ODP_ERR("Group not created: %i\n", grp);
		return -1;
	}

	prio_grp_mask_set(prio, grp);

	odp_ticketlock_unlock(&sched->grp_lock);

	spread = allocate_spread(grp, prio);

	sched->queue[queue_index].grp  = grp;
	sched->queue[queue_index].prio = prio;
	sched->queue[queue_index].spread = spread;
	sched->queue[queue_index].sync = sched_param->sync;
	sched->queue[queue_index].order_lock_count = sched_param->lock_count;
	sched->queue[queue_index].poll_pktin  = 0;
	sched->queue[queue_index].pktio_index = 0;
	sched->queue[queue_index].pktin_index = 0;

	odp_atomic_init_u64(&sched->order[queue_index].ctx, 0);
	odp_atomic_init_u64(&sched->order[queue_index].next_ctx, 0);

	for (i = 0; i < CONFIG_QUEUE_MAX_ORD_LOCKS; i++)
		odp_atomic_init_u64(&sched->order[queue_index].lock[i], 0);

	return 0;
}

static inline uint8_t sched_sync_type(uint32_t queue_index)
{
	return sched->queue[queue_index].sync;
}

static void schedule_destroy_queue(uint32_t queue_index)
{
	int grp  = sched->queue[queue_index].grp;
	int prio = sched->queue[queue_index].prio;
	int spread = sched->queue[queue_index].spread;

	dec_queue_count(grp, prio, spread);

	odp_ticketlock_lock(&sched->grp_lock);
	prio_grp_mask_clear(prio, grp);
	odp_ticketlock_unlock(&sched->grp_lock);

	sched->queue[queue_index].grp    = 0;
	sched->queue[queue_index].prio   = 0;
	sched->queue[queue_index].spread = 0;

	if ((sched_sync_type(queue_index) == ODP_SCHED_SYNC_ORDERED) &&
	    odp_atomic_load_u64(&sched->order[queue_index].ctx) !=
	    odp_atomic_load_u64(&sched->order[queue_index].next_ctx))
		_ODP_ERR("queue reorder incomplete\n");
}

static int schedule_sched_queue(uint32_t queue_index)
{
	int grp      = sched->queue[queue_index].grp;
	int prio     = sched->queue[queue_index].prio;
	int spread   = sched->queue[queue_index].spread;
	ring_mpmc_rst_u32_t *ring = &sched->prio_q[grp][prio][spread].ring;

	ring_mpmc_rst_u32_enq(ring, sched->ring_mask, queue_index);
	return 0;
}

static void schedule_pktio_start(int pktio_index, int num_pktin,
				 int pktin_idx[], odp_queue_t queue[])
{
	int i;
	uint32_t qi;

	sched->pktio[pktio_index].num_pktin = num_pktin;

	for (i = 0; i < num_pktin; i++) {
		qi = queue_to_index(queue[i]);
		sched->queue[qi].poll_pktin  = 1;
		sched->queue[qi].pktio_index = pktio_index;
		sched->queue[qi].pktin_index = pktin_idx[i];

		_ODP_ASSERT(pktin_idx[i] <= MAX_PKTIN_INDEX);

		/* Start polling */
		_odp_sched_queue_set_status(qi, QUEUE_STATUS_SCHED);
		schedule_sched_queue(qi);
	}
}

static inline void release_atomic(void)
{
	uint32_t qi  = sched_local.stash.qi;
	ring_mpmc_rst_u32_t *ring = sched_local.stash.ring;

	/* Release current atomic queue */
	ring_mpmc_rst_u32_enq(ring, sched->ring_mask, qi);

	/* We don't hold sync context anymore */
	sched_local.sync_ctx = NO_SYNC_CONTEXT;
}

static void schedule_release_atomic(void)
{
	if (sched_local.sync_ctx == ODP_SCHED_SYNC_ATOMIC &&
	    sched_local.stash.num_ev == 0)
		release_atomic();
}

static inline int ordered_own_turn(uint32_t queue_index)
{
	uint64_t ctx;

	ctx = odp_atomic_load_acq_u64(&sched->order[queue_index].ctx);

	return ctx == sched_local.ordered.ctx;
}

static inline void wait_for_order(uint32_t queue_index)
{
	/* Busy loop to synchronize ordered processing */
	while (1) {
		if (ordered_own_turn(queue_index))
			break;
		odp_cpu_pause();
	}
}

/**
 * Perform stashed enqueue operations
 *
 * Should be called only when already in order.
 */
static inline void ordered_stash_release(void)
{
	int i;

	for (i = 0; i < sched_local.ordered.stash_num; i++) {
		odp_queue_t queue;
		_odp_event_hdr_t **event_hdr;
		int num, num_enq;

		queue = sched_local.ordered.stash[i].queue;
		event_hdr = sched_local.ordered.stash[i].event_hdr;
		num = sched_local.ordered.stash[i].num;

		num_enq = odp_queue_enq_multi(queue,
					      (odp_event_t *)event_hdr, num);

		/* Drop packets that were not enqueued */
		if (odp_unlikely(num_enq < num)) {
			if (odp_unlikely(num_enq < 0))
				num_enq = 0;

			_ODP_DBG("Dropped %i packets\n", num - num_enq);
			_odp_event_free_multi(&event_hdr[num_enq], num - num_enq);
		}
	}
	sched_local.ordered.stash_num = 0;
}

static inline void release_ordered(void)
{
	uint32_t qi;
	uint32_t i;

	qi = sched_local.ordered.src_queue;

	wait_for_order(qi);

	/* Release all ordered locks */
	for (i = 0; i < sched->queue[qi].order_lock_count; i++) {
		if (!sched_local.ordered.lock_called.u8[i])
			odp_atomic_store_rel_u64(&sched->order[qi].lock[i],
						 sched_local.ordered.ctx + 1);
	}

	sched_local.ordered.lock_called.all = 0;
	sched_local.ordered.in_order = 0;

	/* We don't hold sync context anymore */
	sched_local.sync_ctx = NO_SYNC_CONTEXT;

	ordered_stash_release();

	/* Next thread can continue processing */
	odp_atomic_add_rel_u64(&sched->order[qi].ctx, 1);
}

static void schedule_release_ordered(void)
{
	if (odp_unlikely((sched_local.sync_ctx != ODP_SCHED_SYNC_ORDERED) ||
			 sched_local.stash.num_ev))
		return;

	release_ordered();
}

static int schedule_term_local(void)
{
	if (sched_local.stash.num_ev) {
		_ODP_ERR("Locally pre-scheduled events exist.\n");
		return -1;
	}

	if (sched_local.sync_ctx == ODP_SCHED_SYNC_ATOMIC)
		schedule_release_atomic();
	else if (sched_local.sync_ctx == ODP_SCHED_SYNC_ORDERED)
		schedule_release_ordered();

	return 0;
}

static void schedule_config_init(odp_schedule_config_t *config)
{
	config->num_groups = sched->config_if.max_groups;
	config->num_group_prios = sched->config_if.max_group_prios;
	config->prio.min = sched->config_if.min_prio;
	config->prio.num = sched->config_if.max_prios;
	config->num_queues = sched->max_queues;
	config->queue_size = _odp_queue_glb->config.max_queue_size;
	config->sched_group.all = sched->config_if.group_enable.all;
	config->sched_group.control = sched->config_if.group_enable.control;
	config->sched_group.worker = sched->config_if.group_enable.worker;
}

static int check_group_prios(const odp_schedule_group_param_t *param, int min_prio, int max_prio)
{
	int prev = -1, level;

	for (uint32_t i = 0; i < param->prio.num; ++i) {
		level = param->prio.level[i];

		if (level <= prev || level < min_prio || level > max_prio)
			return 0;

		prev = level;
	}

	return 1;
}

static void set_group_prios(odp_schedule_group_t group, const odp_schedule_group_param_t *param)
{
	if (param->prio.num == 0)
		return;

	for (uint32_t i = 0; i < param->prio.num; ++i)
		sched->sched_grp[group].level[i] = param->prio.level[i];

	sched->sched_grp[group].num_prio = param->prio.num;
}

static void schedule_group_clear(odp_schedule_group_t group)
{
	odp_thrmask_t zero;

	odp_thrmask_zero(&zero);

	if (group < 0 || group > ODP_SCHED_GROUP_CONTROL)
		_ODP_ABORT("Invalid scheduling group\n");

	grp_update_mask(group, &zero);
	sched->sched_grp[group].allocated = 0;
}

static uint32_t get_inc_groups(const odp_schedule_config_t *config)
{
	uint32_t num = 0;

	if (config->sched_group.all)
		num++;

	if (config->sched_group.control)
		num++;

	if (config->sched_group.worker)
		num++;

	return num;
}

static uint32_t get_inc_group_prios(const odp_schedule_config_t *config)
{
	uint32_t num = 0;
	const uint32_t def = config->prio.num;

	if (config->sched_group.all) {
		if (config->sched_group.all_param.prio.num > 0)
			num += config->sched_group.all_param.prio.num;
		else
			num += def;
	}

	if (config->sched_group.control) {
		if (config->sched_group.control_param.prio.num > 0)
			num += config->sched_group.control_param.prio.num;
		else
			num += def;
	}

	if (config->sched_group.worker) {
		if (config->sched_group.worker_param.prio.num > 0)
			num += config->sched_group.worker_param.prio.num;
		else
			num += def;
	}

	return num;
}

static int schedule_config(const odp_schedule_config_t *config)
{
	const int max_prio = config->prio.min + config->prio.num - 1;
	const uint32_t inc_grps = get_inc_groups(config),
	inc_grp_prios = get_inc_group_prios(config);

	if (config->num_groups > sched->config_if.max_groups) {
		_ODP_ERR("Bad number of groups %u\n", config->num_groups);
		return -1;
	}

	if (config->num_group_prios > sched->config_if.max_group_prios) {
		_ODP_ERR("Bad number of group priorities %u\n", config->num_group_prios);
		return -1;
	}

	if (config->prio.num > sched->config_if.max_prios) {
		_ODP_ERR("Bad number of priorities %u\n", config->prio.num);
		return -1;
	}

	if (config->prio.min < sched->config_if.min_prio) {
		_ODP_ERR("Bad minimum priority %u\n", config->prio.min);
		return -1;
	}

	if (max_prio > sched->config_if.max_prio) {
		_ODP_ERR("Bad maximum priority %u\n", max_prio);
		return -1;
	}

	if (inc_grps > config->num_groups) {
		_ODP_ERR("Insufficient groups (required: %u, configured: %u)\n", inc_grps,
			 config->num_groups);
		return -1;
	}

	if (inc_grp_prios > config->num_group_prios) {
		_ODP_ERR("Insufficient group priorities (required: %u, configured: %u)\n",
			 inc_grp_prios, config->num_group_prios);
		return -1;
	}

	if (!check_group_prios(&config->sched_group.all_param, config->prio.min, max_prio) ||
	    !check_group_prios(&config->sched_group.worker_param, config->prio.min, max_prio) ||
	    !check_group_prios(&config->sched_group.control_param, config->prio.min, max_prio)) {
		_ODP_ERR("Bad predefined group priority range\n");
		return -1;
	}

	odp_ticketlock_lock(&sched->grp_lock);
	sched->config_if.group_enable.all = config->sched_group.all;
	sched->config_if.group_enable.control = config->sched_group.control;
	sched->config_if.group_enable.worker = config->sched_group.worker;
	sched->config_if.max_groups = config->num_groups;
	sched->config_if.max_group_prios = config->num_group_prios;
	sched->config_if.max_prios = config->prio.num;
	sched->config_if.min_prio = config->prio.min;
	sched->config_if.max_prio = max_prio;
	sched->config_if.def_prio = (sched->config_if.max_prio - sched->config_if.min_prio) / 2 +
				    sched->config_if.min_prio;

	for (int i = 0; i < NUM_SCHED_GRPS; i++) {
		for (uint32_t j = 0; j < sched->config_if.max_prios; ++j)
			sched->sched_grp[i].level[j] = sched->config_if.min_prio + j;

		sched->sched_grp[i].num_prio = sched->config_if.max_prios;
	}

	set_group_prios(ODP_SCHED_GROUP_ALL, &config->sched_group.all_param);
	set_group_prios(ODP_SCHED_GROUP_WORKER, &config->sched_group.worker_param);
	set_group_prios(ODP_SCHED_GROUP_CONTROL, &config->sched_group.control_param);

	/* Remove existing threads from predefined scheduling groups. */
	if (!config->sched_group.all)
		schedule_group_clear(ODP_SCHED_GROUP_ALL);

	if (!config->sched_group.worker)
		schedule_group_clear(ODP_SCHED_GROUP_WORKER);

	if (!config->sched_group.control)
		schedule_group_clear(ODP_SCHED_GROUP_CONTROL);

	sched->num_grps += inc_grps;
	sched->num_grp_prios += inc_grp_prios;

	odp_ticketlock_unlock(&sched->grp_lock);

	return 0;
}

/* Spread load after adding 'num' queues */
static inline uint32_t spread_load(int grp, int prio, int spr, int num)
{
	uint32_t num_q, num_thr;

	num_q   = sched->prio_q_count[grp][prio][spr];
	num_thr = sched->sched_grp[grp].spread_thrs[spr];

	if (num_thr == 0)
		return UINT32_MAX;

	return ((num_q + num) * QUEUE_LOAD) / num_thr;
}

static inline int balance_spread(int grp, int prio, int cur_spr)
{
	int spr;
	uint64_t cur_load, min_load, load;
	int num_spread = sched->config.num_spread;
	int new_spr = cur_spr;

	cur_load = spread_load(grp, prio, cur_spr, 0);
	min_load = cur_load;

	for (spr = 0; spr < num_spread; spr++) {
		if (spr == cur_spr)
			continue;

		load = spread_load(grp, prio, spr, 1);

		/* Move queue if improvement is larger than marginal */
		if ((load + QUEUE_LOAD_MARGIN) < min_load) {
			new_spr  = spr;
			min_load = load;
		}
	}

	return new_spr;
}

static inline int copy_from_stash(odp_event_t *restrict out_ev, uint32_t max)
{
	int i = 0;

	while (sched_local.stash.num_ev && max) {
		out_ev[i] = sched_local.stash.ev[sched_local.stash.ev_index];
		sched_local.stash.ev_index++;
		sched_local.stash.num_ev--;
		max--;
		i++;
	}

	return i;
}

static int schedule_ord_enq_multi(odp_queue_t dst_queue, void *event_hdr[],
				  int num, int *ret)
{
	int i;
	uint32_t stash_num;
	queue_entry_t *dst_qentry;
	uint32_t src_queue;

	/* This check is done for every queue enqueue operation, also for plain
	 * queues. Return fast when not holding a scheduling context. */
	if (odp_likely(sched_local.sync_ctx != ODP_SCHED_SYNC_ORDERED))
		return 0;

	if (sched_local.ordered.in_order)
		return 0;

	dst_qentry = qentry_from_handle(dst_queue);

	if (dst_qentry->param.order == ODP_QUEUE_ORDER_IGNORE)
		return 0;

	src_queue  = sched_local.ordered.src_queue;
	stash_num  = sched_local.ordered.stash_num;

	if (ordered_own_turn(src_queue)) {
		/* Own turn, so can do enqueue directly. */
		sched_local.ordered.in_order = 1;
		ordered_stash_release();
		return 0;
	}

	/* Pktout may drop packets, so the operation cannot be stashed. */
	if (dst_qentry->pktout.pktio != ODP_PKTIO_INVALID ||
	    odp_unlikely(stash_num >=  sched->config.order_stash_size)) {
		/* If the local stash is full, wait until it is our turn and
		 * then release the stash and do enqueue directly. */
		wait_for_order(src_queue);

		sched_local.ordered.in_order = 1;

		ordered_stash_release();
		return 0;
	}

	sched_local.ordered.stash[stash_num].queue = dst_queue;
	sched_local.ordered.stash[stash_num].num = num;
	for (i = 0; i < num; i++)
		sched_local.ordered.stash[stash_num].event_hdr[i] = event_hdr[i];

	sched_local.ordered.stash_num++;

	*ret = num;
	return 1;
}

static int schedule_ord_enq_multi_no_stash(odp_queue_t dst_queue,
					   void *event_hdr[] ODP_UNUSED,
					   int num ODP_UNUSED, int *ret ODP_UNUSED)
{
	queue_entry_t *dst_qentry;
	uint32_t src_queue;

	if (odp_likely(sched_local.sync_ctx != ODP_SCHED_SYNC_ORDERED))
		return 0;
	if (sched_local.ordered.in_order)
		return 0;

	dst_qentry = qentry_from_handle(dst_queue);
	if (dst_qentry->param.order == ODP_QUEUE_ORDER_IGNORE)
		return 0;

	src_queue  = sched_local.ordered.src_queue;
	if (odp_unlikely(!ordered_own_turn(src_queue)))
		wait_for_order(src_queue);

	sched_local.ordered.in_order = 1;
	return 0;
}

static inline int queue_is_pktin(uint32_t queue_index)
{
	return sched->queue[queue_index].poll_pktin;
}

static inline int poll_pktin(uint32_t qi, int direct_recv,
			     odp_event_t ev_tbl[], int max_num)
{
	int pktio_index, pktin_index, num, num_pktin;
	_odp_event_hdr_t **hdr_tbl;
	int ret;
	void *q_int;
	_odp_event_hdr_t *b_hdr[CONFIG_BURST_SIZE];

	hdr_tbl = (_odp_event_hdr_t **)ev_tbl;

	if (!direct_recv) {
		hdr_tbl = b_hdr;

		/* Limit burst to max queue enqueue size */
		if (max_num > CONFIG_BURST_SIZE)
			max_num = CONFIG_BURST_SIZE;
	}

	pktio_index = sched->queue[qi].pktio_index;
	pktin_index = sched->queue[qi].pktin_index;

	num = _odp_sched_cb_pktin_poll(pktio_index, pktin_index, hdr_tbl, max_num);

	if (num == 0)
		return 0;

	/* Pktio stopped or closed. Call stop_finalize when we have stopped
	 * polling all pktin queues of the pktio. */
	if (odp_unlikely(num < 0)) {
		odp_ticketlock_lock(&sched->pktio_lock);
		sched->pktio[pktio_index].num_pktin--;
		num_pktin = sched->pktio[pktio_index].num_pktin;
		odp_ticketlock_unlock(&sched->pktio_lock);

		_odp_sched_queue_set_status(qi, QUEUE_STATUS_NOTSCHED);

		if (num_pktin == 0)
			_odp_sched_cb_pktio_stop_finalize(pktio_index);

		return num;
	}

	if (direct_recv)
		return num;

	q_int = qentry_from_index(qi);

	ret = odp_queue_enq_multi(q_int, (odp_event_t *)b_hdr, num);

	/* Drop packets that were not enqueued */
	if (odp_unlikely(ret < num)) {
		int num_enq = ret;

		if (odp_unlikely(ret < 0))
			num_enq = 0;

		_ODP_DBG("Dropped %i packets\n", num - num_enq);
		_odp_event_free_multi(&b_hdr[num_enq], num - num_enq);
	}

	return ret;
}

static inline int schedule_grp_prio(odp_queue_t *out_queue, odp_event_t out_ev[], uint32_t max_num,
				    int grp, int prio, int first_spr, int balance)
{
	int spr, new_spr, i, ret;
	uint32_t qi;
	int num_spread = sched->config.num_spread;
	uint32_t ring_mask = sched->ring_mask;
	const uint32_t burst_def_sync[NUM_SCHED_SYNC] = {
		sched->config.burst_default[ODP_SCHED_SYNC_PARALLEL][prio],
		sched->config.burst_default[ODP_SCHED_SYNC_ATOMIC][prio],
		sched->config.burst_default[ODP_SCHED_SYNC_ORDERED][prio]};
	const uint32_t burst_max_sync[NUM_SCHED_SYNC] = {
		sched->config.burst_max[ODP_SCHED_SYNC_PARALLEL][prio],
		sched->config.burst_max[ODP_SCHED_SYNC_ATOMIC][prio],
		sched->config.burst_max[ODP_SCHED_SYNC_ORDERED][prio]};

	/* Select the first spread based on weights */
	spr = first_spr;

	for (i = 0; i < num_spread;) {
		int num;
		uint8_t sync_ctx, ordered;
		odp_queue_t handle;
		ring_mpmc_rst_u32_t *ring;
		int pktin;
		uint32_t max_deq;
		int stashed = 1;
		odp_event_t *ev_tbl = sched_local.stash.ev;

		if (spr >= num_spread)
			spr = 0;

		/* No queues allocated to this spread */
		if (odp_unlikely((sched->prio_q_mask[grp][prio] & (1 << spr)) == 0)) {
			i++;
			spr++;
			continue;
		}

		ring = &sched->prio_q[grp][prio][spr].ring;

		/* Get queue index from the spread queue */
		if (ring_mpmc_rst_u32_deq(ring, ring_mask, &qi) == 0) {
			/* Spread queue is empty */
			i++;
			spr++;
			continue;
		}

		sync_ctx = sched_sync_type(qi);
		ordered  = (sync_ctx == ODP_SCHED_SYNC_ORDERED);
		max_deq = burst_def_sync[sync_ctx];

		/* When application's array is larger than default burst
		 * size, output all events directly there. Also, ordered
		 * queues are not stashed locally to improve
		 * parallelism. Ordered context can only be released
		 * when the local cache is empty. */
		if (max_num > max_deq || ordered) {
			const uint32_t burst_max = burst_max_sync[sync_ctx];

			stashed = 0;
			ev_tbl  = out_ev;
			max_deq = max_num;
			if (max_num > burst_max)
				max_deq = burst_max;
		}

		pktin = queue_is_pktin(qi);

		/* Update queue spread before dequeue. Dequeue changes status of an empty
		 * queue, which enables a following enqueue operation to insert the queue
		 * back into scheduling (with new spread). */
		if (odp_unlikely(balance)) {
			new_spr = balance_spread(grp, prio, spr);

			if (new_spr != spr) {
				sched->queue[qi].spread = new_spr;
				ring = &sched->prio_q[grp][prio][new_spr].ring;
				update_queue_count(grp, prio, spr, new_spr);
			}
		}

		num = _odp_sched_queue_deq(qi, ev_tbl, max_deq, !pktin);

		if (odp_unlikely(num < 0)) {
			/* Remove destroyed queue from scheduling. Continue scheduling
			 * the same group/prio/spread. */
			continue;
		}

		if (num == 0) {
			int direct_recv = !ordered;
			int num_pkt;

			if (!pktin) {
				/* Remove empty queue from scheduling */
				continue;
			}

			/* Poll packet input queue */
			num_pkt = poll_pktin(qi, direct_recv, ev_tbl, max_deq);

			if (odp_unlikely(num_pkt < 0)) {
				/* Pktio has been stopped or closed. Stop polling
				 * the packet input queue. */
				continue;
			}

			if (num_pkt == 0 || !direct_recv) {
				/* No packets to be returned. Continue scheduling
				 * packet input queue even when it is empty. */
				ring_mpmc_rst_u32_enq(ring, ring_mask, qi);

				/* Continue scheduling from the next spread */
				i++;
				spr++;
				continue;
			}

			/* Process packets from an atomic or parallel queue right away. */
			num = num_pkt;
		}

		if (ordered) {
			uint64_t ctx;
			odp_atomic_u64_t *next_ctx;

			next_ctx = &sched->order[qi].next_ctx;
			ctx = odp_atomic_fetch_inc_u64(next_ctx);

			sched_local.ordered.ctx = ctx;
			sched_local.ordered.src_queue = qi;

			/* Continue scheduling ordered queues */
			ring_mpmc_rst_u32_enq(ring, ring_mask, qi);
			sched_local.sync_ctx = sync_ctx;

		} else if (sync_ctx == ODP_SCHED_SYNC_ATOMIC) {
			/* Hold queue during atomic access */
			sched_local.stash.qi   = qi;
			sched_local.stash.ring = ring;
			sched_local.sync_ctx   = sync_ctx;
		} else {
			/* Continue scheduling parallel queues */
			ring_mpmc_rst_u32_enq(ring, ring_mask, qi);
		}

		handle = queue_from_index(qi);

		if (stashed) {
			sched_local.stash.num_ev   = num;
			sched_local.stash.ev_index = 0;
			sched_local.stash.queue    = handle;
			ret = copy_from_stash(out_ev, max_num);
		} else {
			sched_local.stash.num_ev = 0;
			ret = num;
		}

		/* Output the source queue handle */
		if (out_queue)
			*out_queue = handle;

		return ret;
	}

	return 0;
}

/*
 * Schedule queues
 */
static inline int do_schedule(odp_queue_t *out_q, odp_event_t out_ev[], uint32_t max_num)
{
	int i, num_grp, ret, spr, first_id, grp_id, grp, prio;
	uint32_t sched_round;
	uint16_t spread_round;
	uint32_t epoch;
	uint64_t my_groups;
	int balance = 0;

	if (sched_local.stash.num_ev) {
		ret = copy_from_stash(out_ev, max_num);

		if (out_q)
			*out_q = sched_local.stash.queue;

		return ret;
	}

	/* Release schedule context */
	if (sched_local.sync_ctx == ODP_SCHED_SYNC_ATOMIC)
		release_atomic();
	else if (sched_local.sync_ctx == ODP_SCHED_SYNC_ORDERED)
		release_ordered();

	if (odp_unlikely(sched_local.pause))
		return 0;

	sched_round = sched_local.sched_round++;

	/* Each thread prefers a priority queue. Spread weight table avoids
	 * starvation of other priority queues on low thread counts. */
	spread_round = sched_local.spread_round;

	if (odp_likely(sched->load_balance)) {
		/* Spread balance is checked max_spread times in every BALANCE_ROUNDS_M1 + 1
		 * scheduling rounds. */
		if (odp_unlikely(sched_local.balance_on)) {
			balance = 1;

			if (sched_local.balance_start == spread_round)
				sched_local.balance_on = 0;
		}

		if (odp_unlikely((sched_round & BALANCE_ROUNDS_M1) == 0)) {
			sched_local.balance_start = spread_round;
			sched_local.balance_on    = 1;
		}
	}

	if (odp_unlikely(spread_round + 1 >= sched->max_spread))
		sched_local.spread_round = 0;
	else
		sched_local.spread_round = spread_round + 1;

	spr = sched_local.spread_tbl[spread_round];

	epoch = odp_atomic_load_acq_u32(&sched->grp_epoch);
	num_grp = sched_local.num_grp;

	if (odp_unlikely(sched_local.grp_epoch != epoch)) {
		num_grp = grp_update_tbl();
		sched_local.grp_epoch = epoch;
	}

	if (odp_unlikely(num_grp == 0))
		return 0;

	my_groups = sched_local.grp_mask;
	first_id = sched_local.grp_idx;
	sched_local.grp_idx = (first_id + 1) % num_grp;

	for (prio = 0; prio < NUM_PRIO; prio++) {
		grp_id = first_id;

		if (prio_grp_mask_check(prio, my_groups) == 0) {
			/* My groups do not have queues at this priority level, continue to
			 * the next level.
			 *
			 * As a performance optimization, prio_grp_mask[] is checked without
			 * taking the lock. Masks change infrequently and usage of an old mask
			 * just leads into searching events from old priority levels,
			 * new levels are likely used on the next schedule call. */
			continue;
		}

		for (i = 0; i < num_grp; i++) {
			grp = sched_local.grp[grp_id];

			grp_id++;
			if (odp_unlikely(grp_id >= num_grp))
				grp_id = 0;

			if (sched->prio_q_mask[grp][prio] == 0) {
				/* Group does not have queues at this priority level */
				continue;
			}

			/* Schedule events from the selected group and priority level */
			ret = schedule_grp_prio(out_q, out_ev, max_num, grp, prio, spr, balance);

			if (odp_likely(ret))
				return ret;
		}
	}

	return 0;
}

static inline int schedule_run(odp_queue_t *out_queue, odp_event_t out_ev[], uint32_t max_num)
{
	timer_run(1);

	return do_schedule(out_queue, out_ev, max_num);
}

static inline int schedule_loop(odp_queue_t *out_queue, uint64_t wait,
				odp_event_t out_ev[], uint32_t max_num)
{
	odp_time_t next;
	int first = 1;
	int ret;

	while (1) {
		ret = do_schedule(out_queue, out_ev, max_num);
		if (ret) {
			timer_run(2);
			break;
		}
		timer_run(1);

		if (wait == ODP_SCHED_WAIT)
			continue;

		if (wait == ODP_SCHED_NO_WAIT)
			break;

		if (first) {
			next = odp_time_add_ns(odp_time_local(), wait);
			first = 0;
			continue;
		}

		if (odp_time_cmp(next, odp_time_local()) < 0)
			break;
	}

	return ret;
}

static inline int schedule_loop_sleep(odp_queue_t *out_queue, uint64_t wait,
				      odp_event_t out_ev[], uint32_t max_num)
{
	int ret;
	odp_time_t start, end, current, start_sleep;
	int first = 1, sleep = 0;

	while (1) {
		ret = do_schedule(out_queue, out_ev, max_num);
		if (ret) {
			timer_run(2);
			break;
		}
		uint64_t next = timer_run(sleep ? TIMER_SCAN_FORCE : 1);

		if (first) {
			start = odp_time_local();
			start_sleep = odp_time_add_ns(start, sched->powersave.poll_time);
			if (wait != ODP_SCHED_WAIT)
				end = odp_time_add_ns(start, wait);
			first = 0;
			continue;
		}

		if (sleep && next) {
			uint64_t sleep_nsec = _ODP_MIN(sched->powersave.sleep_time, next);

			if (wait != ODP_SCHED_WAIT) {
				uint64_t nsec_to_end = odp_time_diff_ns(end, current);

				sleep_nsec = _ODP_MIN(sleep_nsec, nsec_to_end);
			}

			struct timespec ts = { 0, sleep_nsec };

			nanosleep(&ts, NULL);
		}

		if (!sleep || wait != ODP_SCHED_WAIT)
			current = odp_time_local();

		if (!sleep && odp_time_cmp(start_sleep, current) < 0)
			sleep = 1;

		if (wait != ODP_SCHED_WAIT && odp_time_cmp(end, current) < 0)
			break;
	}

	return ret;
}

static odp_event_t schedule(odp_queue_t *out_queue, uint64_t wait)
{
	odp_event_t ev;

	ev = ODP_EVENT_INVALID;

	schedule_loop(out_queue, wait, &ev, 1);

	return ev;
}

static odp_event_t schedule_sleep(odp_queue_t *out_queue, uint64_t wait)
{
	odp_event_t ev;

	ev = ODP_EVENT_INVALID;

	if (wait == ODP_SCHED_NO_WAIT)
		schedule_loop(out_queue, wait, &ev, 1);
	else
		schedule_loop_sleep(out_queue, wait, &ev, 1);

	return ev;
}

static int schedule_multi(odp_queue_t *out_queue, uint64_t wait,
			  odp_event_t events[], int num)
{
	return schedule_loop(out_queue, wait, events, num);
}

static int schedule_multi_sleep(odp_queue_t *out_queue, uint64_t wait,
				odp_event_t events[], int num)
{
	if (wait == ODP_SCHED_NO_WAIT)
		return schedule_loop(out_queue, wait, events, num);

	return schedule_loop_sleep(out_queue, wait, events, num);
}

static int schedule_multi_no_wait(odp_queue_t *out_queue, odp_event_t events[],
				  int num)
{
	return schedule_run(out_queue, events, num);
}

static int schedule_multi_wait(odp_queue_t *out_queue, odp_event_t events[],
			       int num)
{
	int ret;

	do {
		ret = schedule_run(out_queue, events, num);
	} while (ret == 0);

	return ret;
}

static int schedule_multi_wait_sleep(odp_queue_t *out_queue, odp_event_t events[],
				     int num)
{
	return schedule_loop_sleep(out_queue, ODP_SCHED_WAIT, events, num);
}

static inline void order_lock(void)
{
	if (sched_local.sync_ctx != ODP_SCHED_SYNC_ORDERED)
		return;

	wait_for_order(sched_local.ordered.src_queue);
}

static void order_unlock(void)
{
	/* Nothing to do */
}

static void schedule_order_lock(uint32_t lock_index)
{
	odp_atomic_u64_t *ord_lock;
	uint32_t queue_index;

	if (sched_local.sync_ctx != ODP_SCHED_SYNC_ORDERED)
		return;

	queue_index = sched_local.ordered.src_queue;

	_ODP_ASSERT(lock_index <= sched->queue[queue_index].order_lock_count &&
		    !sched_local.ordered.lock_called.u8[lock_index]);

	ord_lock = &sched->order[queue_index].lock[lock_index];

	/* Busy loop to synchronize ordered processing */
	while (1) {
		uint64_t lock_seq;

		lock_seq = odp_atomic_load_acq_u64(ord_lock);

		if (lock_seq == sched_local.ordered.ctx) {
			sched_local.ordered.lock_called.u8[lock_index] = 1;
			return;
		}
		odp_cpu_pause();
	}
}

static void schedule_order_unlock(uint32_t lock_index)
{
	odp_atomic_u64_t *ord_lock;
	uint32_t queue_index;

	if (sched_local.sync_ctx != ODP_SCHED_SYNC_ORDERED)
		return;

	queue_index = sched_local.ordered.src_queue;

	_ODP_ASSERT(lock_index <= sched->queue[queue_index].order_lock_count);

	ord_lock = &sched->order[queue_index].lock[lock_index];

	_ODP_ASSERT(sched_local.ordered.ctx == odp_atomic_load_u64(ord_lock));

	odp_atomic_store_rel_u64(ord_lock, sched_local.ordered.ctx + 1);
}

static void schedule_order_unlock_lock(uint32_t unlock_index,
				       uint32_t lock_index)
{
	schedule_order_unlock(unlock_index);
	schedule_order_lock(lock_index);
}

static void schedule_order_lock_start(uint32_t lock_index)
{
	(void)lock_index;
}

static void schedule_order_lock_wait(uint32_t lock_index)
{
	schedule_order_lock(lock_index);
}

static void schedule_pause(void)
{
	sched_local.pause = 1;
}

static void schedule_resume(void)
{
	sched_local.pause = 0;
}

static uint64_t schedule_wait_time(uint64_t ns)
{
	return ns;
}

static inline void spread_thrs_inc(odp_schedule_group_t group, int thr_tbl[], int count)
{
	int thr, i;
	uint8_t spread;

	for (i = 0; i < count; i++) {
		thr = thr_tbl[i];
		spread = spread_from_index(thr);
		sched->sched_grp[group].spread_thrs[spread]++;
	}
}

static inline void spread_thrs_dec(odp_schedule_group_t group, int thr_tbl[], int count)
{
	int thr, i;
	uint8_t spread;

	for (i = 0; i < count; i++) {
		thr = thr_tbl[i];
		spread = spread_from_index(thr);
		sched->sched_grp[group].spread_thrs[spread]--;
	}
}

static inline int threads_from_mask(int thr_tbl[], int count, const odp_thrmask_t *mask)
{
	int i;
	int thr = odp_thrmask_first(mask);

	for (i = 0; i < count; i++) {
		if (thr < 0) {
			_ODP_ERR("No more threads in the mask\n");
			return -1;
		}

		thr_tbl[i] = thr;
		thr = odp_thrmask_next(mask, thr);
	}

	return 0;
}

static odp_schedule_group_t allocate_group(const char *name, const odp_thrmask_t *mask,
					   int *thr_tbl, uint32_t num_prio, int num_thr)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;

	if (sched->num_grps >= sched->config_if.max_groups) {
		_ODP_ERR("Maximum number of groups created\n");
		return group;
	}

	if (sched->num_grp_prios + num_prio > sched->config_if.max_group_prios) {
		_ODP_ERR("Insufficient group priorities (attempted: %u, left: %u)\n",
			 num_prio, sched->config_if.max_group_prios - sched->num_grp_prios);
		return group;
	}

	for (int i = SCHED_GROUP_NAMED; i < NUM_SCHED_GRPS; i++) {
		if (!sched->sched_grp[i].allocated) {
			char *grp_name = sched->sched_grp[i].name;

			if (name == NULL)
				grp_name[0] = 0;
			else
				_odp_strcpy(grp_name, name,
					    ODP_SCHED_GROUP_NAME_LEN);

			grp_update_mask(i, mask);
			group = (odp_schedule_group_t)i;
			spread_thrs_inc(group, thr_tbl, num_thr);
			sched->sched_grp[i].allocated = 1;
			sched->num_grps++;
			sched->num_grp_prios += num_prio;
			break;
		}
	}

	return group;
}

static odp_schedule_group_t schedule_group_create(const char *name,
						  const odp_thrmask_t *mask)
{
	odp_schedule_group_t group;
	int count;

	count = odp_thrmask_count(mask);
	if (count < 0) {
		_ODP_ERR("Bad thread count\n");
		return ODP_SCHED_GROUP_INVALID;
	}

	int thr_tbl[ODP_THREAD_COUNT_MAX];

	if (count && threads_from_mask(thr_tbl, count, mask))
		return ODP_SCHED_GROUP_INVALID;

	odp_ticketlock_lock(&sched->grp_lock);
	group = allocate_group(name, mask, thr_tbl, sched->config_if.max_prios, count);
	odp_ticketlock_unlock(&sched->grp_lock);

	return group;
}

static odp_schedule_group_t schedule_group_create_2(const char *name,
						    const odp_thrmask_t *mask,
						    const odp_schedule_group_param_t *param)
{
	odp_schedule_group_t group;
	int count;

	if (!check_group_prios(param, sched->config_if.min_prio, sched->config_if.max_prio)) {
		_ODP_ERR("Bad priority range\n");
		return ODP_SCHED_GROUP_INVALID;
	}

	count = odp_thrmask_count(mask);
	if (count < 0) {
		_ODP_ERR("Bad thread count\n");
		return ODP_SCHED_GROUP_INVALID;
	}

	int thr_tbl[ODP_THREAD_COUNT_MAX];

	if (count && threads_from_mask(thr_tbl, count, mask))
		return ODP_SCHED_GROUP_INVALID;

	odp_ticketlock_lock(&sched->grp_lock);
	group = allocate_group(name, mask, thr_tbl,
			       param->prio.num > 0 ? param->prio.num : sched->config_if.max_prios,
			       count);

	if (group != ODP_SCHED_GROUP_INVALID)
		set_group_prios(group, param);

	odp_ticketlock_unlock(&sched->grp_lock);

	return group;
}

static int schedule_group_destroy(odp_schedule_group_t group)
{
	odp_thrmask_t zero;
	int i;

	if (group >= NUM_SCHED_GRPS || group < SCHED_GROUP_NAMED) {
		_ODP_ERR("Bad group %i\n", group);
		return -1;
	}

	odp_thrmask_zero(&zero);

	odp_ticketlock_lock(&sched->grp_lock);

	if (sched->sched_grp[group].allocated == 0) {
		odp_ticketlock_unlock(&sched->grp_lock);
		_ODP_ERR("Group not created: %i\n", group);
		return -1;
	}

	grp_update_mask(group, &zero);

	for (i = 0; i < MAX_SPREAD; i++)
		sched->sched_grp[group].spread_thrs[i] = 0;

	memset(sched->sched_grp[group].name, 0, ODP_SCHED_GROUP_NAME_LEN);
	sched->sched_grp[group].allocated = 0;
	sched->num_grps--;
	sched->num_grp_prios -= sched->sched_grp[group].num_prio;

	odp_ticketlock_unlock(&sched->grp_lock);
	return 0;
}

static odp_schedule_group_t schedule_group_lookup(const char *name)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	int i;

	odp_ticketlock_lock(&sched->grp_lock);

	for (i = SCHED_GROUP_NAMED; i < NUM_SCHED_GRPS; i++) {
		if (strcmp(name, sched->sched_grp[i].name) == 0) {
			group = (odp_schedule_group_t)i;
			break;
		}
	}

	odp_ticketlock_unlock(&sched->grp_lock);
	return group;
}

static int schedule_group_join(odp_schedule_group_t group, const odp_thrmask_t *mask)
{
	int i, count, thr;
	odp_thrmask_t new_mask;

	if (group >= NUM_SCHED_GRPS || group < SCHED_GROUP_NAMED) {
		_ODP_ERR("Bad group %i\n", group);
		return -1;
	}

	count = odp_thrmask_count(mask);
	if (count <= 0) {
		_ODP_ERR("No threads in the mask\n");
		return -1;
	}

	int thr_tbl[count];

	thr = odp_thrmask_first(mask);
	for (i = 0; i < count; i++) {
		if (thr < 0) {
			_ODP_ERR("No more threads in the mask\n");
			return -1;
		}

		thr_tbl[i] = thr;
		thr = odp_thrmask_next(mask, thr);
	}

	odp_ticketlock_lock(&sched->grp_lock);

	if (sched->sched_grp[group].allocated == 0) {
		odp_ticketlock_unlock(&sched->grp_lock);
		_ODP_ERR("Bad group status\n");
		return -1;
	}

	spread_thrs_inc(group, thr_tbl, count);

	odp_thrmask_or(&new_mask, &sched->sched_grp[group].mask, mask);
	grp_update_mask(group, &new_mask);

	odp_ticketlock_unlock(&sched->grp_lock);
	return 0;
}

static int schedule_group_leave(odp_schedule_group_t group, const odp_thrmask_t *mask)
{
	int i, count, thr;
	odp_thrmask_t new_mask;

	if (group >= NUM_SCHED_GRPS || group < SCHED_GROUP_NAMED) {
		_ODP_ERR("Bad group %i\n", group);
		return -1;
	}

	count = odp_thrmask_count(mask);
	if (count <= 0) {
		_ODP_ERR("No threads in the mask\n");
		return -1;
	}

	int thr_tbl[count];

	thr = odp_thrmask_first(mask);
	for (i = 0; i < count; i++) {
		if (thr < 0) {
			_ODP_ERR("No more threads in the mask\n");
			return -1;
		}

		thr_tbl[i] = thr;
		thr = odp_thrmask_next(mask, thr);
	}

	odp_thrmask_xor(&new_mask, mask, &sched->mask_all);

	odp_ticketlock_lock(&sched->grp_lock);

	if (sched->sched_grp[group].allocated == 0) {
		odp_ticketlock_unlock(&sched->grp_lock);
		_ODP_ERR("Bad group status\n");
		return -1;
	}

	spread_thrs_dec(group, thr_tbl, count);

	odp_thrmask_and(&new_mask, &sched->sched_grp[group].mask, &new_mask);
	grp_update_mask(group, &new_mask);

	odp_ticketlock_unlock(&sched->grp_lock);
	return 0;
}

static int schedule_group_thrmask(odp_schedule_group_t group,
				  odp_thrmask_t *thrmask)
{
	int ret;

	odp_ticketlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && sched->sched_grp[group].allocated) {
		*thrmask = sched->sched_grp[group].mask;
		ret = 0;
	} else {
		ret = -1;
	}

	odp_ticketlock_unlock(&sched->grp_lock);
	return ret;
}

static int schedule_group_info(odp_schedule_group_t group,
			       odp_schedule_group_info_t *info)
{
	int ret;

	odp_ticketlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && sched->sched_grp[group].allocated) {
		info->name    = sched->sched_grp[group].name;
		info->thrmask = sched->sched_grp[group].mask;
		info->num     = sched->sched_grp[group].num_prio;

		for (int i = 0; i < info->num; i++)
			info->level[i] = sched->sched_grp[group].level[i];

		ret = 0;
	} else {
		ret = -1;
	}

	odp_ticketlock_unlock(&sched->grp_lock);
	return ret;
}

static int schedule_thr_add(odp_schedule_group_t group, int thr)
{
	odp_thrmask_t mask;
	odp_thrmask_t new_mask;

	if (group < 0 || group >= SCHED_GROUP_NAMED)
		return -1;

	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr);

	odp_ticketlock_lock(&sched->grp_lock);

	if (!sched->sched_grp[group].allocated) {
		odp_ticketlock_unlock(&sched->grp_lock);
		return 0;
	}

	odp_thrmask_or(&new_mask, &sched->sched_grp[group].mask, &mask);
	spread_thrs_inc(group, &thr, 1);
	grp_update_mask(group, &new_mask);

	odp_ticketlock_unlock(&sched->grp_lock);

	return 0;
}

static int schedule_thr_rem(odp_schedule_group_t group, int thr)
{
	odp_thrmask_t mask;
	odp_thrmask_t new_mask;

	if (group < 0 || group >= SCHED_GROUP_NAMED)
		return -1;

	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr);
	odp_thrmask_xor(&new_mask, &mask, &sched->mask_all);

	odp_ticketlock_lock(&sched->grp_lock);

	if (!sched->sched_grp[group].allocated) {
		odp_ticketlock_unlock(&sched->grp_lock);
		return 0;
	}

	odp_thrmask_and(&new_mask, &sched->sched_grp[group].mask, &new_mask);
	spread_thrs_dec(group, &thr, 1);
	grp_update_mask(group, &new_mask);

	odp_ticketlock_unlock(&sched->grp_lock);

	return 0;
}

static void schedule_prefetch(int num)
{
	(void)num;
}

static void schedule_get_config(schedule_config_t *config)
{
	*config = sched->config_if;
}

static int schedule_capability(odp_schedule_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_schedule_capability_t));

	capa->max_ordered_locks = schedule_max_ordered_locks();
	capa->max_groups = sched->config_if.max_groups;
	capa->max_group_prios = sched->config_if.max_group_prios;
	capa->min_prio = sched->config_if.min_prio;
	capa->max_prios = sched->config_if.max_prios;
	capa->max_queues = sched->max_queues;
	capa->max_queue_size = _odp_queue_glb->config.max_queue_size;
	capa->max_flow_id = BUF_HDR_MAX_FLOW_ID;
	capa->order_wait = ODP_SUPPORT_YES;

	return 0;
}

static void schedule_print(void)
{
	int spr, prio, grp, pos;
	uint32_t num_queues, num_active;
	ring_mpmc_rst_u32_t *ring;
	odp_schedule_capability_t capa;
	int num_spread = sched->config.num_spread;
	const int col_width = 24;
	const int size = 512;
	char str[size];

	(void)schedule_capability(&capa);

	_ODP_PRINT("\nScheduler debug info\n");
	_ODP_PRINT("--------------------\n");
	_ODP_PRINT("  scheduler:         basic\n");
	_ODP_PRINT("  max groups:        %u\n", capa.max_groups);
	_ODP_PRINT("  max priorities:    %u\n", capa.max_prios);
	_ODP_PRINT("  num spread:        %i\n", num_spread);
	_ODP_PRINT("  prefer ratio:      %u\n", sched->config.prefer_ratio);
	_ODP_PRINT("\n");

	pos  = 0;
	pos += _odp_snprint(&str[pos], size - pos, "  Number of active event queues:\n");
	pos += _odp_snprint(&str[pos], size - pos, "              spread\n");
	pos += _odp_snprint(&str[pos], size - pos, "            ");

	for (spr = 0; spr < num_spread; spr++)
		pos += _odp_snprint(&str[pos], size - pos, " %7i", spr);

	_ODP_PRINT("%s\n", str);

	for (prio = 0; prio < NUM_PRIO; prio++) {
		for (grp = 0; grp < NUM_SCHED_GRPS; grp++)
			if (sched->prio_q_mask[grp][prio])
				break;

		if (grp == NUM_SCHED_GRPS)
			continue;

		_ODP_PRINT("  prio: %i\n", prio);

		for (grp = 0; grp < NUM_SCHED_GRPS; grp++) {
			if (sched->sched_grp[grp].allocated == 0)
				continue;

			pos  = 0;
			pos += _odp_snprint(&str[pos], size - pos, "    group %i:", grp);

			for (spr = 0; spr < num_spread; spr++) {
				num_queues = sched->prio_q_count[grp][prio][spr];
				ring = &sched->prio_q[grp][prio][spr].ring;
				num_active = ring_mpmc_rst_u32_len(ring);
				pos += _odp_snprint(&str[pos], size - pos, " %3u/%3u",
						    num_active, num_queues);
			}

			_ODP_PRINT("%s\n", str);
		}
	}

	_ODP_PRINT("\n  Number of threads per schedule group:\n");
	_ODP_PRINT("             name                     spread\n");

	for (grp = 0; grp < NUM_SCHED_GRPS; grp++) {
		if (sched->sched_grp[grp].allocated == 0)
			continue;

		pos  = 0;
		pos += _odp_snprint(&str[pos], size - pos, "    group %i: %-*s", grp, col_width,
				    sched->sched_grp[grp].name);

		for (spr = 0; spr < num_spread; spr++)
			pos += _odp_snprint(&str[pos], size - pos, " %u",
					    sched->sched_grp[grp].spread_thrs[spr]);

		_ODP_PRINT("%s\n", str);
	}

	_ODP_PRINT("\n");
}

/* Returns spread for queue debug prints */
int _odp_sched_basic_get_spread(uint32_t queue_index)
{
	return sched->queue[queue_index].spread;
}

const _odp_schedule_api_fn_t _odp_schedule_basic_api;
const _odp_schedule_api_fn_t _odp_schedule_basic_sleep_api;

static const _odp_schedule_api_fn_t *sched_api(void)
{
	if (sched->powersave.poll_time > 0)
		return &_odp_schedule_basic_sleep_api;

	return &_odp_schedule_basic_api;
}

/* Fill in scheduler interface */
schedule_fn_t _odp_schedule_basic_fn = {
	.pktio_start = schedule_pktio_start,
	.thr_add = schedule_thr_add,
	.thr_rem = schedule_thr_rem,
	.create_queue = schedule_create_queue,
	.destroy_queue = schedule_destroy_queue,
	.sched_queue = schedule_sched_queue,
	.ord_enq_multi = schedule_ord_enq_multi,
	.init_global = schedule_init_global,
	.term_global = schedule_term_global,
	.init_local  = schedule_init_local,
	.term_local  = schedule_term_local,
	.order_lock = order_lock,
	.order_unlock = order_unlock,
	.max_ordered_locks = schedule_max_ordered_locks,
	.get_config = schedule_get_config,
	.sched_api = sched_api,
};

/* Fill in scheduler API calls */
const _odp_schedule_api_fn_t _odp_schedule_basic_api = {
	.schedule_wait_time       = schedule_wait_time,
	.schedule_capability      = schedule_capability,
	.schedule_config_init     = schedule_config_init,
	.schedule_config          = schedule_config,
	.schedule                 = schedule,
	.schedule_multi           = schedule_multi,
	.schedule_multi_wait      = schedule_multi_wait,
	.schedule_multi_no_wait   = schedule_multi_no_wait,
	.schedule_pause           = schedule_pause,
	.schedule_resume          = schedule_resume,
	.schedule_release_atomic  = schedule_release_atomic,
	.schedule_release_ordered = schedule_release_ordered,
	.schedule_prefetch        = schedule_prefetch,
	.schedule_min_prio        = schedule_min_prio,
	.schedule_max_prio        = schedule_max_prio,
	.schedule_default_prio    = schedule_default_prio,
	.schedule_num_prio        = schedule_num_prio,
	.schedule_group_create    = schedule_group_create,
	.schedule_group_create_2  = schedule_group_create_2,
	.schedule_group_destroy   = schedule_group_destroy,
	.schedule_group_lookup    = schedule_group_lookup,
	.schedule_group_join      = schedule_group_join,
	.schedule_group_leave     = schedule_group_leave,
	.schedule_group_thrmask   = schedule_group_thrmask,
	.schedule_group_info      = schedule_group_info,
	.schedule_order_lock      = schedule_order_lock,
	.schedule_order_unlock    = schedule_order_unlock,
	.schedule_order_unlock_lock = schedule_order_unlock_lock,
	.schedule_order_lock_start  = schedule_order_lock_start,
	.schedule_order_lock_wait   = schedule_order_lock_wait,
	.schedule_order_wait      = order_lock,
	.schedule_print           = schedule_print
};

/* API functions used when powersave is enabled in the config file. */
const _odp_schedule_api_fn_t _odp_schedule_basic_sleep_api = {
	.schedule_wait_time       = schedule_wait_time,
	.schedule_capability      = schedule_capability,
	.schedule_config_init     = schedule_config_init,
	.schedule_config          = schedule_config,
	/* Only the following *_sleep functions differ from _odp_schedule_basic_api */
	.schedule                 = schedule_sleep,
	.schedule_multi           = schedule_multi_sleep,
	.schedule_multi_wait      = schedule_multi_wait_sleep,
	/* End of powersave specific functions */
	.schedule_multi_no_wait   = schedule_multi_no_wait,
	.schedule_pause           = schedule_pause,
	.schedule_resume          = schedule_resume,
	.schedule_release_atomic  = schedule_release_atomic,
	.schedule_release_ordered = schedule_release_ordered,
	.schedule_prefetch        = schedule_prefetch,
	.schedule_min_prio        = schedule_min_prio,
	.schedule_max_prio        = schedule_max_prio,
	.schedule_default_prio    = schedule_default_prio,
	.schedule_num_prio        = schedule_num_prio,
	.schedule_group_create    = schedule_group_create,
	.schedule_group_create_2  = schedule_group_create_2,
	.schedule_group_destroy   = schedule_group_destroy,
	.schedule_group_lookup    = schedule_group_lookup,
	.schedule_group_join      = schedule_group_join,
	.schedule_group_leave     = schedule_group_leave,
	.schedule_group_thrmask   = schedule_group_thrmask,
	.schedule_group_info      = schedule_group_info,
	.schedule_order_lock      = schedule_order_lock,
	.schedule_order_unlock    = schedule_order_unlock,
	.schedule_order_unlock_lock = schedule_order_unlock_lock,
	.schedule_order_lock_start  = schedule_order_lock_start,
	.schedule_order_lock_wait   = schedule_order_lock_wait,
	.schedule_order_wait      = order_lock,
	.schedule_print           = schedule_print
};
