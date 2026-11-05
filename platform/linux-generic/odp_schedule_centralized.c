/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2019-2026 Nokia
 */

/* Centralized scheduler
 *
 * Scheduling work is offloaded to a small number of dedicated service
 * threads. Worker threads publish a per-thread request slot; an assigned
 * service thread drains the request and returns events.
 *
 * Fast path:
 *   - Per-(prio, grp) MPMC restricted-size ring of ready queue indices.
 *   - Per-priority 64-bit ready_grp_mask (bit g = group g has work at this
 *     priority). do_schedule() does NUM_PRIO bit scans and one ring
 *     dequeue per call.
 *   - Per-worker cache-aligned request slot served by exactly one service
 *     thread (assigned by 'thread_id % num_services'). The worker announces
 *     a request by setting its bit in the service's pending bitmask and
 *     spins on an atomic state instead of going through a queue layer.
 *   - Stash drain and atomic/ordered context release are done on the
 *     worker side before the request is handed off, so the service thread
 *     never waits for order and many calls are pure cache hits. */

#include <odp_posix_extensions.h>

#include <odp/api/align.h>
#include <odp/api/atomic.h>
#include <odp/api/cpu.h>
#include <odp/api/hints.h>
#include <odp/api/packet_io.h>
#include <odp/api/schedule.h>
#include <odp/api/shared_memory.h>
#include <odp/api/sync.h>
#include <odp/api/thread.h>
#include <odp/api/thrmask.h>
#include <odp/api/ticketlock.h>
#include <odp/api/time.h>

#include <odp/api/abi/wait_until.h>

#include <odp/api/plat/atomic_inlines.h>
#include <odp/api/plat/queue_inlines.h>
#include <odp/api/plat/schedule_inline_types.h>
#include <odp/api/plat/thread_inlines.h>
#include <odp/api/plat/thread_inline_types.h>
#include <odp/api/plat/time_inlines.h>

#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_event_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_macros_internal.h>
#include <odp_queue_basic_internal.h>
#include <ring/odp_ring_mpmc_rst_u32_internal.h>
#include <odp_schedule_if.h>
#include <odp_string_internal.h>
#include <odp_timer_internal.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* No synchronization context */
#define NO_SYNC_CONTEXT ODP_SCHED_SYNC_PARALLEL

/* Number of priority levels */
#define NUM_PRIO 8

/* Number of scheduling groups (must equal the width of the ready mask). */
#define NUM_GRP 64

/* Start of named groups in group mask arrays */
#define SCHED_GROUP_NAMED (ODP_SCHED_GROUP_CONTROL + 1)

/* Number of scheduled queue synchronization types */
#define NUM_SCHED_SYNC 3

ODP_STATIC_ASSERT(ODP_SCHED_SYNC_PARALLEL == 0, "ODP_SCHED_SYNC_PARALLEL_value_changed");
ODP_STATIC_ASSERT(ODP_SCHED_SYNC_ATOMIC == 1, "ODP_SCHED_SYNC_ATOMIC_value_changed");
ODP_STATIC_ASSERT(ODP_SCHED_SYNC_ORDERED == 2, "ODP_SCHED_SYNC_ORDERED_value_changed");

/* Upper limit for configurable per-priority burst sizes. */
#define STASH_SIZE CONFIG_BURST_SIZE
#define BURST_MAX  255

/* Sanity upper bound for the runtime 'order_stash_size' config value.
 * Raise if a real use case needs more. */
#define MAX_ORDERED_STASH 512

/* Maximum number of service threads. */
#define MAX_CENTRALIZED_CORES 12

/* Number of 64-bit words needed to cover one bit per ODP thread. */
#define PENDING_WORDS ((ODP_THREAD_COUNT_MAX + 63) / 64)

/* Maximum number of packet IO interfaces */
#define NUM_PKTIO CONFIG_PKTIO_ENTRIES

/* Maximum pktin index. Needs to fit into 8 bits. */
#define MAX_PKTIN_INDEX 255

/* Ring size must hold all queue indices in the worst case. */
#define MAX_RING_SIZE CONFIG_MAX_SCHED_QUEUES

ODP_STATIC_ASSERT(_ODP_CHECK_IS_POWER2(CONFIG_MAX_SCHED_QUEUES),
		  "Number_of_queues_is_not_power_of_two");
ODP_STATIC_ASSERT(_ODP_CHECK_IS_POWER2(MAX_RING_SIZE), "Ring_size_is_not_power_of_two");
ODP_STATIC_ASSERT(NUM_GRP == 64, "NUM_GRP_must_be_64");
ODP_STATIC_ASSERT(ODP_THREAD_COUNT_MAX < (64 * 1024), "Max_64k_threads_supported");

/* Worker request slot state machine. */
#define SLOT_IDLE    0u
#define SLOT_REQUEST 1u
#define SLOT_DONE    2u

/* Storage for stashed enqueue operation arguments (ordered). */
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

/* Per-worker scheduler context. Lives inside worker_slot_t and is touched
 * by both the worker thread (stash drain, sync ctx release on the worker
 * side) and the assigned service thread (do_schedule). The atomic state in
 * worker_slot_t serializes their access, worker reads/writes 'local' only
 * before issuing REQUEST and after observing DONE; the service reads/writes
 * 'local' only between those two events. Cache-line ownership therefore
 * flips at most twice per request, so we pack the hot worker meta and
 * sync-ctx state together in the first line and keep the bulky event stash
 * and ordered backing array on their own cold lines. */
typedef struct ODP_ALIGNED_CACHE {
	/* First cache line: worker hot meta + sync ctx + group state. */
	struct {
		odp_queue_t          queue;
		ring_mpmc_rst_u32_t *ring;
		uint32_t            *ring_data;
		uint32_t             qi;
		uint16_t             num_ev;
		uint16_t             ev_index;
	} stash;

	uint64_t grp_mask;
	uint32_t grp_epoch;
	uint16_t thr;
	uint8_t  sync_ctx;
	uint8_t  pause;
	/* Cold: stash event backing array. */
	odp_event_t stash_ev[CONFIG_BURST_SIZE] ODP_ALIGNED_CACHE;

	/* Cold: ordered-context state. */
	struct {
		uint64_t         ctx;
		/* size = order_stash_size, or NULL */
		ordered_stash_t *stash;
		int              stash_num;
		uint32_t         src_queue;
		lock_called_t    lock_called;
		uint8_t          in_order;
	} ordered;
} sched_local_t;

/* Per-worker request slot: lock-free handoff to one assigned service.
 *
 * Three cache lines on the hot path. The worker waits in WFE on 'state'
 * (line A) after issuing REQUEST. If the service's pre-DONE stores to
 * 'from'/'num_got' shared that line they would each wake the WFE monitor
 * before the meaningful DONE store, so the response outputs are kept on
 * their own line B.
 *
 * Request inputs share line A with 'state' deliberately. The worker
 * writes the inputs and sets 'state' to REQUEST before publishing the
 * request through the service's pending bitmask (release), and does not
 * touch them again until DONE is observed, so the WFE monitor on the
 * line is dormant while the service reads the inputs. The service's only
 * write to line A is the final store_rel(state, DONE), which wakes the
 * waiting worker.
 *
 *   line A: request inputs + 'state' atomic
 *           - worker writes inputs, REQUEST, sets pending bit (release),
 *             waits in WFE; service reads inputs, store_rel DONE (sole
 *             writer of this line while worker is waiting)
 *   line B: response outputs
 *           - service writes both fields before every DONE, worker only
 *             reads them, so the line moves service -> worker only
 *   line C+: sched_local_t */
typedef struct ODP_ALIGNED_CACHE {
	/* worker output buffer */
	odp_event_t     *evs;
	/* ODP_SCHED_WAIT, ODP_SCHED_NO_WAIT or absolute ns */
	uint64_t         deadline_ns;
	uint32_t         num_max;
	/* assigned service thread */
	uint8_t          service_idx;
	/* SLOT_IDLE / SLOT_REQUEST / SLOT_DONE */
	odp_atomic_u32_t state;
	odp_queue_t      from ODP_ALIGNED_CACHE;
	uint32_t         num_got;
	sched_local_t    local ODP_ALIGNED_CACHE;
} worker_slot_t;

/* Per (prio, grp) priority queue: ring of ready queue indices. */
typedef struct ODP_ALIGNED_CACHE {
	/* Ring header */
	ring_mpmc_rst_u32_t ring;
	/* Ring data: ready queue indices */
	uint32_t queue_index[MAX_RING_SIZE];
} prio_queue_t;

/* Order context of a queue. */
typedef struct ODP_ALIGNED_CACHE {
	odp_atomic_u64_t ctx ODP_ALIGNED_CACHE;
	odp_atomic_u64_t next_ctx;
	odp_atomic_u64_t lock[CONFIG_QUEUE_MAX_ORD_LOCKS];
} order_context_t;

/* Per-service pending-request bitmask. */
typedef struct ODP_ALIGNED_CACHE {
	odp_atomic_u64_t pending[PENDING_WORDS];
} svc_pending_t;

/* Global scheduler state. */
typedef struct {
	struct {
		/* Per (sync type, internal priority) burst limits. Internal
		 * priority 0 is the highest (i.e. the inversion of the API
		 * priority). */
		uint8_t  burst_default[NUM_SCHED_SYNC][NUM_PRIO];
		uint8_t  burst_max[NUM_SCHED_SYNC][NUM_PRIO];
		uint16_t order_stash_size;
	} config;

	uint32_t ring_mask;
	odp_shm_t shm;

	/* Per-priority bitmask of groups that currently have ready work.
	 * Bit g set => prio_q[p][g] ring has at least one ready queue. Best
	 * effort: stale entries are tolerated and cleaned up opportunistically
	 * in do_schedule. */
	struct ODP_ALIGNED_CACHE {
		odp_atomic_u64_t mask;
	} ready_grp_mask[NUM_PRIO];

	/* Per (prio, grp) ring of ready queue indices. */
	prio_queue_t prio_q[NUM_PRIO][NUM_GRP];

	/* Per-queue metadata. */
	struct {
		uint8_t grp;
		/* Inverted prio: max API prio = 0, min API prio = NUM_PRIO-1. */
		uint8_t prio;
		uint8_t sync;
		uint8_t order_lock_count;
		uint8_t poll_pktin;
		uint8_t pktio_index;
		uint8_t pktin_index;
	} queue[CONFIG_MAX_SCHED_QUEUES];

	order_context_t order[CONFIG_MAX_SCHED_QUEUES];
	/* Group state. */
	odp_ticketlock_t grp_lock;
	odp_atomic_u32_t grp_epoch;
	odp_thrmask_t    mask_all;

	struct {
		char           name[ODP_SCHED_GROUP_NAME_LEN];
		odp_thrmask_t  mask;
		uint8_t        allocated;
		uint8_t        level[NUM_PRIO];
		uint32_t       num_prio;
	} sched_grp[NUM_GRP];

	/* Polled pktin bookkeeping (for stop_finalize). */
	struct {
		int num_pktin;
	} pktio[NUM_PKTIO];

	odp_ticketlock_t pktio_lock;

	/* Service thread state. */
	struct {
		odp_atomic_u32_t is_running;
		uint32_t         num_threads;
		odp_cpumask_t    mask;
		_odp_service_thread_t thread[MAX_CENTRALIZED_CORES];
	} svc;

	/* Scheduler interface config options (not used in fast path) */
	schedule_config_t config_if;
	uint32_t max_queues;
	uint32_t num_grps;
	uint32_t num_grp_prios;
	/* Per-worker request slots (indexed by ODP thread id) and
	 * per-service pending-request bitmasks. Bit t in svc_pending[svc].pending[t/64]
	 * is set by the worker after it transitions its slot to SLOT_REQUEST
	 * and is drained (via xchg) by the assigned service before it
	 * processes the slot. */
	worker_slot_t worker_slot_arr[ODP_THREAD_COUNT_MAX] ODP_ALIGNED_CACHE;
	svc_pending_t svc_pending_arr[MAX_CENTRALIZED_CORES] ODP_ALIGNED_CACHE;
} sched_global_t;

/* Single global scheduler instance. */
static sched_global_t *sched;
static worker_slot_t *worker_slot;
static svc_pending_t *svc_pending;

extern schedule_fn_t _odp_schedule_centralized_fn;
static int schedule_ord_enq_multi_no_stash(odp_queue_t dst_queue, void *event_hdr[],
					   int num, int *ret);

/* ---------------------- helpers ---------------------- */

static inline int inverse_prio(int api_prio)
{
	return sched->config_if.max_prio - api_prio;
}

/* Release: pairs with the acquire fence after mask_clear_ready() in do_schedule() so that a
 * consumer which clears this bit also observes the preceding ring enqueue. */
static inline void mask_set_ready(int prio, int grp)
{
	odp_atomic_bit_set_rel_u64(&sched->ready_grp_mask[prio].mask, (uint64_t)1 << grp);
}

static inline void mask_clear_ready(int prio, int grp)
{
	odp_atomic_bit_clr_u64(&sched->ready_grp_mask[prio].mask, (uint64_t)1 << grp);
}

static inline uint64_t mask_load(int prio)
{
	return odp_atomic_load_u64(&sched->ready_grp_mask[prio].mask);
}

static inline uint8_t sched_sync_type(uint32_t qi)
{
	return sched->queue[qi].sync;
}

/* Mark slot 'thr' as pending in service 'svc_idx'. The service learns about requests only
 * through this bit, so it must be set with release semantics after all request inputs and
 * 'local' updates. Pairs with the acquire fence in service_main(). */
static inline void notify_service(int svc_idx, int thr)
{
	odp_atomic_bit_set_rel_u64(&svc_pending[svc_idx].pending[thr / 64],
				   (uint64_t)1 << (thr % 64));
}

/* ---------------------- config ---------------------- */

static int read_burst_size_conf(uint8_t out_tbl[], const char *conf_str,
				int min_val, int max_val, int print)
{
	int burst_val[NUM_PRIO];
	const int max_len = 256;
	const int n = max_len - 1;
	char line[max_len];
	int len = 0;

	if (_odp_libconfig_lookup_array(conf_str, burst_val, NUM_PRIO) != NUM_PRIO) {
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

static int read_config_file(sched_global_t *s)
{
	const char *str;
	int val = 0;
	char val_str[64];

	_ODP_PRINT("!!! WARNING: centralized scheduler is highly experimental !!!\n");
	_ODP_PRINT("Scheduler config:\n");

	str = "sched_centralized.num_centralized";

	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	if (val < 1 || val > MAX_CENTRALIZED_CORES) {
		_ODP_ERR("Bad value %s = %i [min: 1, max: %u]\n", str, val,
			 MAX_CENTRALIZED_CORES);
		return -1;
	}

	s->svc.num_threads = val;
	_ODP_PRINT("  %s: %i\n", str, val);

	str = "sched_centralized.centralized_cpumask";

	if (!_odp_libconfig_lookup_str(str, val_str, sizeof(val_str) - 1)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	odp_cpumask_from_str(&s->svc.mask, val_str);

	if ((uint32_t)odp_cpumask_count(&s->svc.mask) != s->svc.num_threads) {
		_ODP_ERR("Bad value %s = %s, requires %u CPUs (num_centralized)\n",
			 str, val_str, s->svc.num_threads);
		return -1;
	}

	_ODP_PRINT("  %s: %s\n", str, val_str);

	str = "sched_centralized.order_stash_size";

	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	if (val > MAX_ORDERED_STASH || val < 0) {
		_ODP_ERR("Bad value %s = %i [min: 0, max: %u]\n", str, val, MAX_ORDERED_STASH);
		return -1;
	}

	s->config.order_stash_size = val;
	_ODP_PRINT("  %s: %i\n", str, val);

	/* Per-priority burst limits. First read the type-independent defaults
	 * into all three sync-type tables (printed once), then let the
	 * per-sync-type entries override non-zero values. */
	str = "sched_centralized.burst_size_default";

	if (read_burst_size_conf(s->config.burst_default[ODP_SCHED_SYNC_ATOMIC], str, 1,
				 STASH_SIZE, 1) ||
	    read_burst_size_conf(s->config.burst_default[ODP_SCHED_SYNC_PARALLEL], str, 1,
				 STASH_SIZE, 0) ||
	    read_burst_size_conf(s->config.burst_default[ODP_SCHED_SYNC_ORDERED], str, 1,
				 STASH_SIZE, 0))
		return -1;

	str = "sched_centralized.burst_size_max";

	if (read_burst_size_conf(s->config.burst_max[ODP_SCHED_SYNC_ATOMIC], str, 1,
				 BURST_MAX, 1) ||
	    read_burst_size_conf(s->config.burst_max[ODP_SCHED_SYNC_PARALLEL], str, 1,
				 BURST_MAX, 0) ||
	    read_burst_size_conf(s->config.burst_max[ODP_SCHED_SYNC_ORDERED], str, 1,
				 BURST_MAX, 0))
		return -1;

	if (read_burst_size_conf(s->config.burst_default[ODP_SCHED_SYNC_ATOMIC],
				 "sched_centralized.burst_size_atomic", 0, STASH_SIZE, 1))
		return -1;

	if (read_burst_size_conf(s->config.burst_max[ODP_SCHED_SYNC_ATOMIC],
				 "sched_centralized.burst_size_max_atomic", 0, BURST_MAX, 1))
		return -1;

	if (read_burst_size_conf(s->config.burst_default[ODP_SCHED_SYNC_PARALLEL],
				 "sched_centralized.burst_size_parallel", 0, STASH_SIZE, 1))
		return -1;

	if (read_burst_size_conf(s->config.burst_max[ODP_SCHED_SYNC_PARALLEL],
				 "sched_centralized.burst_size_max_parallel", 0, BURST_MAX, 1))
		return -1;

	if (read_burst_size_conf(s->config.burst_default[ODP_SCHED_SYNC_ORDERED],
				 "sched_centralized.burst_size_ordered", 0, STASH_SIZE, 1))
		return -1;

	if (read_burst_size_conf(s->config.burst_max[ODP_SCHED_SYNC_ORDERED],
				 "sched_centralized.burst_size_max_ordered", 0, BURST_MAX, 1))
		return -1;

	_ODP_PRINT("\n");

	return 0;
}

/* ---------------------- init / term ---------------------- */

static int schedule_init_global(void)
{
	odp_shm_t shm;
	int i, j;

	_ODP_DBG("Schedule init ... ");

	/* TODO: Process memory model currently not compatible with the centralized
	 *       scheduler, due to how worker threads pass output buffers to service
	 *       threads. Need to fix at some point. */
	if (odp_global_ro.init_param.mem_model == ODP_MEM_MODEL_PROCESS) {
		_ODP_ERR("Process mode not supported with centralized scheduler.\n");
		return -1;
	}

	shm = odp_shm_reserve("_odp_sched_centralized_global",
			      sizeof(sched_global_t),
			      ODP_CACHE_LINE_SIZE,
			      0);
	if (shm == ODP_SHM_INVALID) {
		_ODP_ERR("Schedule init: Shm reserve failed.\n");
		return -1;
	}

	sched = odp_shm_addr(shm);
	memset(sched, 0, sizeof(sched_global_t));
	sched->shm = shm;
	worker_slot = sched->worker_slot_arr;
	svc_pending = sched->svc_pending_arr;
	odp_atomic_init_u32(&sched->svc.is_running, 1);

	if (read_config_file(sched)) {
		odp_shm_free(shm);
		return -1;
	}

	if (_odp_service_cpus_reserve(&sched->svc.mask)) {
		_ODP_ERR("Failed to reserve service CPUs\n");
		odp_shm_free(shm);
		return -1;
	}

	if (sched->config.order_stash_size == 0)
		_odp_schedule_centralized_fn.ord_enq_multi = schedule_ord_enq_multi_no_stash;

	sched->ring_mask = MAX_RING_SIZE - 1;

	sched->config_if.group_enable.all     = 1;
	sched->config_if.group_enable.control = 1;
	sched->config_if.group_enable.worker  = 1;
	sched->config_if.max_groups      = NUM_GRP - SCHED_GROUP_NAMED;
	sched->config_if.max_group_prios = NUM_GRP * NUM_PRIO;
	sched->config_if.max_prios       = NUM_PRIO;
	sched->config_if.min_prio        = 0;
	sched->config_if.max_prio        = NUM_PRIO - 1;
	sched->config_if.def_prio        = sched->config_if.max_prio / 2;
	sched->max_queues = sched->ring_mask;

	for (i = 0; i < NUM_PRIO; i++) {
		odp_atomic_init_u64(&sched->ready_grp_mask[i].mask, 0);

		for (j = 0; j < NUM_GRP; j++)
			ring_mpmc_rst_u32_init(&sched->prio_q[i][j].ring);
	}

	odp_ticketlock_init(&sched->grp_lock);
	odp_atomic_init_u32(&sched->grp_epoch, 0);
	odp_ticketlock_init(&sched->pktio_lock);

	for (i = 0; i < NUM_PKTIO; i++)
		sched->pktio[i].num_pktin = 0;

	for (i = 0; i < NUM_GRP; i++) {
		memset(sched->sched_grp[i].name, 0, ODP_SCHED_GROUP_NAME_LEN);
		odp_thrmask_zero(&sched->sched_grp[i].mask);

		for (j = 0; j < (int)sched->config_if.max_prios; j++)
			sched->sched_grp[i].level[j] = sched->config_if.min_prio + j;

		sched->sched_grp[i].num_prio = sched->config_if.max_prios;
	}

	sched->sched_grp[ODP_SCHED_GROUP_ALL].allocated     = 1;
	sched->sched_grp[ODP_SCHED_GROUP_WORKER].allocated  = 1;
	sched->sched_grp[ODP_SCHED_GROUP_CONTROL].allocated = 1;
	_odp_strcpy(sched->sched_grp[ODP_SCHED_GROUP_ALL].name, "__SCHED_GROUP_ALL",
		    ODP_SCHED_GROUP_NAME_LEN);
	_odp_strcpy(sched->sched_grp[ODP_SCHED_GROUP_WORKER].name, "__SCHED_GROUP_WORKER",
		    ODP_SCHED_GROUP_NAME_LEN);
	_odp_strcpy(sched->sched_grp[ODP_SCHED_GROUP_CONTROL].name, "__SCHED_GROUP_CONTROL",
		    ODP_SCHED_GROUP_NAME_LEN);

	odp_thrmask_setall(&sched->mask_all);

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++)
		odp_atomic_init_u32(&worker_slot[i].state, SLOT_IDLE);

	for (i = 0; i < MAX_CENTRALIZED_CORES; i++)
		for (j = 0; j < PENDING_WORDS; j++)
			odp_atomic_init_u64(&svc_pending[i].pending[j], 0);

	_ODP_DBG("done\n");

	return 0;
}

static void drain_ring(int prio, int grp)
{
	ring_mpmc_rst_u32_t *ring = &sched->prio_q[prio][grp].ring;
	uint32_t *ring_data = sched->prio_q[prio][grp].queue_index;
	uint32_t qi;

	while (ring_mpmc_rst_u32_deq(ring, ring_data, sched->ring_mask, &qi)) {
		odp_event_t events[1];
		int num = _odp_sched_queue_deq(qi, events, 1, 1);

		if (num > 0)
			_ODP_ERR("Queue not empty\n");
	}
}

static int schedule_term_global(void)
{
	int rc = 0;

	if (odp_global_rw->schedule_configured == 1) {
		odp_atomic_store_u32(&sched->svc.is_running, 0);

		if (_odp_service_thread_join(sched->svc.thread, sched->svc.num_threads)) {
			_ODP_ERR("Failed to join schedule service threads\n");
			rc = -1;
		}
	}

	for (int p = 0; p < NUM_PRIO; p++)
		for (int g = 0; g < NUM_GRP; g++)
			drain_ring(p, g);

	if (odp_shm_free(sched->shm) < 0) {
		_ODP_ERR("Shm free failed for odp_schedule_centralized\n");
		rc = -1;
	}

	return rc;
}

/* ---------------------- per-thread init / term ---------------------- */

static inline void sched_local_init(sched_local_t *local, int thr)
{
	memset(local, 0, sizeof(*local));
	local->thr         = thr;
	local->sync_ctx    = NO_SYNC_CONTEXT;
	local->stash.queue = ODP_QUEUE_INVALID;
}

static inline void release_atomic(sched_local_t *local);
static inline void release_ordered(sched_local_t *local);

static int schedule_init_local(void)
{
	const int thr = odp_thread_id();
	worker_slot_t *slot = &worker_slot[thr];

	/* Service threads have no slot of their own. */
	if (_odp_this_thread->type == _ODP_THR_INTERNAL)
		return 0;

	sched_local_init(&slot->local, thr);
	odp_atomic_store_u32(&slot->state, SLOT_IDLE);

	if (sched->config.order_stash_size > 0) {
		const size_t bytes = (size_t)sched->config.order_stash_size *
				     sizeof(ordered_stash_t);

		slot->local.ordered.stash = malloc(bytes);

		if (slot->local.ordered.stash == NULL) {
			_ODP_ERR("Ordered stash allocation failed (%zu B)\n", bytes);
			return -1;
		}
	}

	slot->service_idx = (uint32_t)thr % sched->svc.num_threads;

	return 0;
}

static int schedule_term_local(void)
{
	const int thr = odp_thread_id();
	worker_slot_t *slot = &worker_slot[thr];

	if (_odp_this_thread->type == _ODP_THR_INTERNAL)
		return 0;

	if (slot->local.stash.num_ev) {
		_ODP_ERR("Locally pre-scheduled events exist.\n");
		return -1;
	}

	if (slot->local.sync_ctx == ODP_SCHED_SYNC_ATOMIC)
		release_atomic(&slot->local);
	else if (slot->local.sync_ctx == ODP_SCHED_SYNC_ORDERED)
		release_ordered(&slot->local);

	free(slot->local.ordered.stash);
	slot->local.ordered.stash = NULL;

	odp_atomic_store_u32(&slot->state, SLOT_IDLE);

	return 0;
}

/* ---------------------- group / thread bookkeeping ---------------------- */

static inline void grp_update_mask(int grp, const odp_thrmask_t *new_mask)
{
	odp_thrmask_copy(&sched->sched_grp[grp].mask, new_mask);
	odp_atomic_add_rel_u32(&sched->grp_epoch, 1);
}

static inline void grp_update_local(sched_local_t *local)
{
	int thr = local->thr;
	uint64_t mask = 0;

	odp_ticketlock_lock(&sched->grp_lock);

	for (int i = 0; i < NUM_GRP; i++) {
		if (sched->sched_grp[i].allocated == 0)
			continue;

		if (odp_thrmask_isset(&sched->sched_grp[i].mask, thr))
			mask |= (uint64_t)1 << i;
	}

	odp_ticketlock_unlock(&sched->grp_lock);

	local->grp_mask = mask;
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

/* ---------------------- queue / group create / destroy ---------------------- */

static int check_queue_prio(int prio, int grp)
{
	for (uint32_t i = 0; i < sched->sched_grp[grp].num_prio; i++)
		if (prio == sched->sched_grp[grp].level[i])
			return 1;

	return 0;
}

static int schedule_create_queue(uint32_t queue_index,
				 const odp_schedule_param_t *param)
{
	int grp  = param->group;
	int prio = inverse_prio(param->prio);

	if (odp_global_rw->schedule_configured == 0) {
		_ODP_ERR("Scheduler has not been configured\n");
		return -1;
	}

	if (grp < 0 || grp >= NUM_GRP) {
		_ODP_ERR("Bad schedule group %i\n", grp);
		return -1;
	}

	if (!check_queue_prio(param->prio, grp)) {
		_ODP_ERR("Bad priority %i\n", param->prio);
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

	odp_ticketlock_unlock(&sched->grp_lock);

	sched->queue[queue_index].grp              = grp;
	sched->queue[queue_index].prio             = prio;
	sched->queue[queue_index].sync             = param->sync;
	sched->queue[queue_index].order_lock_count = param->lock_count;
	sched->queue[queue_index].poll_pktin       = 0;
	sched->queue[queue_index].pktio_index      = 0;
	sched->queue[queue_index].pktin_index      = 0;

	odp_atomic_init_u64(&sched->order[queue_index].ctx, 0);
	odp_atomic_init_u64(&sched->order[queue_index].next_ctx, 0);

	for (int i = 0; i < CONFIG_QUEUE_MAX_ORD_LOCKS; i++)
		odp_atomic_init_u64(&sched->order[queue_index].lock[i], 0);

	return 0;
}

static void schedule_destroy_queue(uint32_t queue_index)
{
	sched->queue[queue_index].grp  = 0;
	sched->queue[queue_index].prio = 0;

	if (sched_sync_type(queue_index) == ODP_SCHED_SYNC_ORDERED &&
	    odp_atomic_load_u64(&sched->order[queue_index].ctx) !=
	    odp_atomic_load_u64(&sched->order[queue_index].next_ctx))
		_ODP_ERR("queue reorder incomplete\n");
}

static int schedule_sched_queue(uint32_t queue_index)
{
	int grp  = sched->queue[queue_index].grp;
	int prio = sched->queue[queue_index].prio;
	ring_mpmc_rst_u32_t *ring = &sched->prio_q[prio][grp].ring;
	uint32_t *ring_data = sched->prio_q[prio][grp].queue_index;

	ring_mpmc_rst_u32_enq(ring, ring_data, sched->ring_mask, queue_index);
	mask_set_ready(prio, grp);

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

/* ---------------------- atomic / ordered context handling ---------------------- */

static inline void release_atomic(sched_local_t *local)
{
	uint32_t qi = local->stash.qi;
	ring_mpmc_rst_u32_t *ring = local->stash.ring;
	uint32_t *ring_data = local->stash.ring_data;
	int prio = sched->queue[qi].prio;
	int grp  = sched->queue[qi].grp;

	ring_mpmc_rst_u32_enq(ring, ring_data, sched->ring_mask, qi);
	mask_set_ready(prio, grp);

	local->sync_ctx = NO_SYNC_CONTEXT;
}

static void schedule_release_atomic(void)
{
	sched_local_t *local = &worker_slot[odp_thread_id()].local;

	if (local->sync_ctx == ODP_SCHED_SYNC_ATOMIC && local->stash.num_ev == 0)
		release_atomic(local);
}

static inline int ordered_own_turn(uint32_t qi, sched_local_t *local)
{
	uint64_t ctx = odp_atomic_load_acq_u64(&sched->order[qi].ctx);

	return ctx == local->ordered.ctx;
}

static inline void wait_for_order(uint32_t qi, sched_local_t *local)
{
	while (!ordered_own_turn(qi, local))
		odp_cpu_pause();
}

static inline void ordered_stash_release(sched_local_t *local)
{
	for (int i = 0; i < local->ordered.stash_num; i++) {
		odp_queue_t q = local->ordered.stash[i].queue;
		_odp_event_hdr_t **hdr = local->ordered.stash[i].event_hdr;
		int n = local->ordered.stash[i].num;
		int num_enq;

		num_enq = odp_queue_enq_multi(q, (odp_event_t *)hdr, n);

		if (odp_unlikely(num_enq < n)) {
			if (odp_unlikely(num_enq < 0))
				num_enq = 0;

			_ODP_DBG("Dropped %i packets\n", n - num_enq);
			_odp_event_free_multi(&hdr[num_enq], n - num_enq);
		}
	}

	local->ordered.stash_num = 0;
}

static inline void release_ordered(sched_local_t *local)
{
	uint32_t qi = local->ordered.src_queue;

	wait_for_order(qi, local);

	for (uint32_t i = 0; i < sched->queue[qi].order_lock_count; i++) {
		if (!local->ordered.lock_called.u8[i])
			odp_atomic_store_rel_u64(&sched->order[qi].lock[i],
						 local->ordered.ctx + 1);
	}

	local->ordered.lock_called.all = 0;
	local->ordered.in_order        = 0;
	local->sync_ctx                = NO_SYNC_CONTEXT;

	ordered_stash_release(local);

	odp_atomic_add_rel_u64(&sched->order[qi].ctx, 1);
}

static void schedule_release_ordered(void)
{
	sched_local_t *local = &worker_slot[odp_thread_id()].local;

	if (odp_unlikely(local->sync_ctx != ODP_SCHED_SYNC_ORDERED || local->stash.num_ev))
		return;

	release_ordered(local);
}

static int schedule_ord_enq_multi(odp_queue_t dst_queue, void *event_hdr[],
				  int num, int *ret)
{
	sched_local_t *local;
	queue_entry_t *dst_qentry;
	uint32_t src_queue;
	uint32_t stash_num;

	/* This hook is invoked from arbitrary queue-enqueue callers, including
	 * non-ODP threads such as the POSIX timer thread that posts timeouts.
	 * Such threads cannot hold an ordered sync context, so bail out before
	 * indexing into worker_slot[]. */
	if (odp_unlikely(_odp_this_thread == NULL))
		return 0;

	local = &worker_slot[odp_thread_id()].local;

	if (odp_likely(local->sync_ctx != ODP_SCHED_SYNC_ORDERED))
		return 0;

	if (local->ordered.in_order)
		return 0;

	dst_qentry = qentry_from_handle(dst_queue);

	if (dst_qentry->param.order == ODP_QUEUE_ORDER_IGNORE)
		return 0;

	src_queue = local->ordered.src_queue;
	stash_num = local->ordered.stash_num;

	if (ordered_own_turn(src_queue, local)) {
		local->ordered.in_order = 1;
		ordered_stash_release(local);
		return 0;
	}

	if (dst_qentry->pktout.pktio != ODP_PKTIO_INVALID ||
	    odp_unlikely(stash_num >= sched->config.order_stash_size)) {
		wait_for_order(src_queue, local);
		local->ordered.in_order = 1;
		ordered_stash_release(local);
		return 0;
	}

	local->ordered.stash[stash_num].queue = dst_queue;
	local->ordered.stash[stash_num].num   = num;

	for (int i = 0; i < num; i++)
		local->ordered.stash[stash_num].event_hdr[i] = event_hdr[i];

	local->ordered.stash_num++;
	*ret = num;

	return 1;
}

static int schedule_ord_enq_multi_no_stash(odp_queue_t dst_queue,
					   void *event_hdr[] ODP_UNUSED,
					   int num ODP_UNUSED, int *ret ODP_UNUSED)
{
	sched_local_t *local;
	queue_entry_t *dst_qentry;
	uint32_t src_queue;

	if (odp_unlikely(_odp_this_thread == NULL))
		return 0;

	local = &worker_slot[odp_thread_id()].local;

	if (odp_likely(local->sync_ctx != ODP_SCHED_SYNC_ORDERED))
		return 0;

	if (local->ordered.in_order)
		return 0;

	dst_qentry = qentry_from_handle(dst_queue);

	if (dst_qentry->param.order == ODP_QUEUE_ORDER_IGNORE)
		return 0;

	src_queue = local->ordered.src_queue;

	if (odp_unlikely(!ordered_own_turn(src_queue, local)))
		wait_for_order(src_queue, local);

	local->ordered.in_order = 1;

	return 0;
}

static void schedule_ord_stash_release(odp_queue_t dst_queue)
{
	sched_local_t *local;

	if (odp_unlikely(_odp_this_thread == NULL))
		return;

	local = &worker_slot[odp_thread_id()].local;

	if (odp_likely(local->sync_ctx != ODP_SCHED_SYNC_ORDERED))
		return;

	schedule_ord_enq_multi_no_stash(dst_queue, NULL, 0, NULL);

	if (local->ordered.in_order)
		ordered_stash_release(local);
}

/* ---------------------- stash + pktin helpers ---------------------- */

static inline int copy_from_stash(odp_event_t *out_ev, uint32_t max, sched_local_t *local)
{
	int i = 0;

	while (local->stash.num_ev && max) {
		out_ev[i] = local->stash_ev[local->stash.ev_index];
		local->stash.ev_index++;
		local->stash.num_ev--;
		max--;
		i++;
	}

	return i;
}

static inline int queue_is_pktin(uint32_t qi)
{
	return sched->queue[qi].poll_pktin;
}

static inline int poll_pktin(uint32_t qi, int direct_recv,
			     odp_event_t ev_tbl[], int max_num)
{
	int pktio_index = sched->queue[qi].pktio_index;
	int pktin_index = sched->queue[qi].pktin_index;
	_odp_event_hdr_t **hdr_tbl = (_odp_event_hdr_t **)ev_tbl;
	_odp_event_hdr_t *b_hdr[CONFIG_BURST_SIZE];
	int num, num_pktin, ret;
	void *q_int;

	if (!direct_recv) {
		hdr_tbl = b_hdr;

		if (max_num > CONFIG_BURST_SIZE)
			max_num = CONFIG_BURST_SIZE;
	}

	num = _odp_sched_cb_pktin_poll(pktio_index, pktin_index, hdr_tbl, max_num);

	if (num == 0)
		return 0;

	if (odp_unlikely(num < 0)) {
		/* Pktio stopped or closed. Call stop_finalize once all pktins
		 * of the pktio have stopped polling. */
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

	if (odp_unlikely(ret < num)) {
		int num_enq = ret;

		if (odp_unlikely(ret < 0))
			num_enq = 0;

		_ODP_DBG("Dropped %i packets\n", num - num_enq);
		_odp_event_free_multi(&b_hdr[num_enq], num - num_enq);
	}

	return 0;
}

/* ---------------------- core scheduling ---------------------- */

/* Drain events from one queue index, manage sync context, place output in
 * either the worker's output buffer directly or the local stash.
 *
 * Returns:
 *   > 0 : number of events returned to the caller
 *     0 : queue empty (and pktin polling, if applicable, returned nothing
 *         immediately usable); ring re-enq handled where appropriate
 *   < 0 : queue is being destroyed or has stopped pktin polling; drop from
 *         current scheduling round */
static inline int dispatch_queue(odp_queue_t *out_q, odp_event_t out_ev[], uint32_t max_num,
				 uint32_t qi, int prio, int grp,
				 ring_mpmc_rst_u32_t *ring, uint32_t *ring_data,
				 sched_local_t *local)
{
	uint8_t sync_ctx = sched_sync_type(qi);
	int ordered = (sync_ctx == ODP_SCHED_SYNC_ORDERED);
	int pktin = queue_is_pktin(qi);
	uint32_t max_deq = sched->config.burst_default[sync_ctx][prio];
	int stashed = 1;
	odp_event_t *ev_tbl = local->stash_ev;
	odp_queue_t handle;
	int num;
	int ret;

	/* When the caller's array is larger than the configured default burst
	 * size, write directly into it. Ordered queues are never stashed: the
	 * ordered context cannot be released while events remain in the
	 * stash, so stashing limits parallelism. */
	if (max_num > max_deq || ordered) {
		const uint32_t burst_max = sched->config.burst_max[sync_ctx][prio];

		stashed = 0;
		ev_tbl = out_ev;
		max_deq = max_num;

		if (max_deq > burst_max)
			max_deq = burst_max;
	}

	num = _odp_sched_queue_deq(qi, ev_tbl, max_deq, !pktin);

	if (odp_unlikely(num < 0)) {
		/* Queue destroyed. Do NOT clear the group's mask bit -- other
		 * queues may still be in the ring; a later attempt that finds
		 * the ring empty will clear it. */
		return -1;
	}

	if (num == 0) {
		int direct_recv = !ordered;
		int num_pkt;

		if (!pktin) {
			/* Empty regular queue: the queue layer sets
			 * QUEUE_STATUS to NOTSCHED on first dequeue from an
			 * empty queue, and a subsequent enqueue re-inserts it
			 * via schedule_sched_queue. Drop from the ring. */
			return 0;
		}

		num_pkt = poll_pktin(qi, direct_recv, ev_tbl, max_deq);

		if (odp_unlikely(num_pkt < 0)) {
			/* Pktio stopped or closed. Stop polling this pktin
			 * queue. */
			return -1;
		}

		if (num_pkt == 0 || !direct_recv) {
			/* No packets to return directly; keep the pktin queue
			 * scheduled. */
			ring_mpmc_rst_u32_enq(ring, ring_data, sched->ring_mask, qi);
			mask_set_ready(prio, grp);

			return 0;
		}

		/* Process packets from an atomic or parallel queue. */
		num = num_pkt;
	}

	if (ordered) {
		odp_atomic_u64_t *next_ctx = &sched->order[qi].next_ctx;
		uint64_t ctx = odp_atomic_fetch_inc_u64(next_ctx);

		local->ordered.ctx       = ctx;
		local->ordered.src_queue = qi;
		ring_mpmc_rst_u32_enq(ring, ring_data, sched->ring_mask, qi);
		mask_set_ready(prio, grp);
		local->sync_ctx = sync_ctx;
	} else if (sync_ctx == ODP_SCHED_SYNC_ATOMIC) {
		local->stash.qi        = qi;
		local->stash.ring      = ring;
		local->stash.ring_data = ring_data;
		local->sync_ctx        = sync_ctx;
	} else {
		ring_mpmc_rst_u32_enq(ring, ring_data, sched->ring_mask, qi);
		mask_set_ready(prio, grp);
	}

	handle = queue_from_index(qi);

	if (stashed) {
		local->stash.num_ev   = num;
		local->stash.ev_index = 0;
		local->stash.queue    = handle;
		ret = copy_from_stash(out_ev, max_num, local);
	} else {
		local->stash.num_ev = 0;
		ret = num;
	}

	if (out_q)
		*out_q = handle;

	return ret;
}

/* O(1) bitmask-based work fetch on behalf of the worker described by
 * 'local'. The worker's group membership is encoded in local->grp_mask
 * (a 64-bit set of group indices), refreshed lazily via grp_epoch.
 *
 * Caller must ensure that the local stash is drained and any outstanding
 * atomic/ordered sync context has been released before invoking this on a
 * service thread (otherwise the service thread could spin in
 * wait_for_order, deadlocking single-service configurations). Auto-release
 * is done by the worker side in worker_request(). */
static inline int do_schedule(odp_queue_t *out_q, odp_event_t out_ev[], uint32_t max_num,
			      sched_local_t *local)
{
	uint32_t epoch;
	uint64_t my_groups;

	epoch = odp_atomic_load_acq_u32(&sched->grp_epoch);

	if (odp_unlikely(local->grp_epoch != epoch)) {
		grp_update_local(local);
		local->grp_epoch = epoch;
	}

	my_groups = local->grp_mask;

	if (odp_unlikely(my_groups == 0))
		return 0;

	/* prio 0 == highest scheduling priority internally (inverse of API). */
	for (int p = 0; p < NUM_PRIO; p++) {
		uint64_t ready = mask_load(p) & my_groups;

		while (ready) {
			int g = __builtin_ctzll(ready);
			uint64_t bit = (uint64_t)1 << g;
			ring_mpmc_rst_u32_t *ring = &sched->prio_q[p][g].ring;
			uint32_t *ring_data = sched->prio_q[p][g].queue_index;
			uint32_t qi;
			int ret;

			ready &= ~bit;

			if (!ring_mpmc_rst_u32_deq(ring, ring_data, sched->ring_mask, &qi)) {
				/* Stale mask bit: clear it and continue.
				 *
				 * Race: a producer (schedule_sched_queue from
				 * a concurrent enqueue) may have done
				 *   ring_enq(qi); mask_set_ready(p, g);
				 * between our deq returning empty and our
				 * clear below. Our clear would then wipe out
				 * the bit just set by the producer, leaving
				 * the qi in the ring with no mask bit -- the
				 * queue would stay invisible to scheduling
				 * until another enqueue happens to set the
				 * bit again. Close the window by rechecking
				 * the ring after the clear and reinstating
				 * the bit if it's no longer empty. */
				mask_clear_ready(p, g);
				odp_mb_acquire();

				if (ring_mpmc_rst_u32_len(ring) > 0)
					mask_set_ready(p, g);

				continue;
			}

			ret = dispatch_queue(out_q, out_ev, max_num, qi, p, g, ring, ring_data,
					     local);

			if (ret > 0)
				return ret;
			/* ret == 0 (empty queue dropped from sched) or ret < 0
			 * (destroyed): try next group. */
		}
	}

	return 0;
}

/* ---------------------- service thread ---------------------- */

static void service_main(void *arg)
{
	odp_atomic_u32_t *is_running = &sched->svc.is_running;
	const int my_idx = (int)(uintptr_t)arg;

	while (odp_atomic_load_u32(is_running) == 1) {
		uint64_t now = 0;
		int now_valid = 0;
		int any_request = 0;

		/* Drain this service's pending bitmask. We xchg-snapshot a
		 * whole word at a time and scan it with __builtin_ctzll; bits
		 * set after the xchg (newly arrived requests) are picked up on
		 * the next outer iteration. */
		for (int i = 0; i < PENDING_WORDS; i++) {
			uint64_t snap;

			snap = odp_atomic_xchg_u64(&svc_pending[my_idx].pending[i], 0);

			if (!snap)
				continue;

			/* Pairs with the release in notify_service(). */
			odp_mb_acquire();

			if (!any_request) {
				any_request = 1;
				timer_run(1);
			}

			while (snap) {
				int bit = __builtin_ctzll(snap);
				int t = i * 64 + bit;
				worker_slot_t *slot = &worker_slot[t];
				odp_queue_t out = ODP_QUEUE_INVALID;
				uint64_t deadline;
				int ret;

				snap &= snap - 1;

				ret = do_schedule(&out, slot->evs, slot->num_max,
						  &slot->local);

				if (ret > 0) {
					slot->from    = out;
					slot->num_got = ret;
					odp_atomic_store_rel_u32(&slot->state,
								 SLOT_DONE);
					continue;
				}

				deadline = slot->deadline_ns;

				if (deadline == ODP_SCHED_NO_WAIT) {
					slot->from    = ODP_QUEUE_INVALID;
					slot->num_got = 0;
					odp_atomic_store_rel_u32(&slot->state,
								 SLOT_DONE);
					continue;
				}

				if (deadline == ODP_SCHED_WAIT) {
					/* Re-arm so we revisit this slot on
					 * the next outer iteration. */
					notify_service(my_idx, t);
					continue;
				}

				if (!now_valid) {
					now = odp_time_global_strict_ns();
					now_valid = 1;
				}

				if (now >= deadline) {
					slot->from    = ODP_QUEUE_INVALID;
					slot->num_got = 0;
					odp_atomic_store_rel_u32(&slot->state,
								 SLOT_DONE);
				} else {
					notify_service(my_idx, t);
				}
			}
		}

		if (!any_request)
			odp_cpu_pause();
	}
}

static int start_service_threads(void)
{
	_odp_service_thread_param_t param[MAX_CENTRALIZED_CORES];
	int cpu = odp_cpumask_first(&sched->svc.mask);

	for (uint32_t i = 0; i < sched->svc.num_threads; i++) {
		param[i].run = service_main;
		param[i].arg = (void *)(uintptr_t)i;
		param[i].cpu = cpu;
		cpu = odp_cpumask_next(&sched->svc.mask, cpu);
	}

	return _odp_service_thread_create(sched->svc.thread, param, sched->svc.num_threads);
}

/* ---------------------- worker-side API ---------------------- */

static inline uint64_t deadline_from_wait(uint64_t wait)
{
	if (wait == ODP_SCHED_WAIT || wait == ODP_SCHED_NO_WAIT)
		return wait;

	return wait + odp_time_global_strict_ns();
}

static inline int worker_request(odp_queue_t *out_queue, odp_event_t *evs,
				 uint32_t num, uint64_t deadline)
{
	worker_slot_t *slot = &worker_slot[odp_thread_id()];
	sched_local_t *local = &slot->local;

	/* Stash drain from a previous burst without involving the service. */
	if (local->stash.num_ev) {
		int ret = copy_from_stash(evs, num, local);

		if (out_queue)
			*out_queue = local->stash.queue;

		return ret;
	}

	/* Auto-release the current sync context in worker context. Doing it
	 * here (instead of inside the service's do_schedule) avoids the
	 * service spinning in wait_for_order, which would deadlock when only
	 * one service thread is configured, and keeps the cache lines hot on
	 * the thread that just produced them. */
	if (local->sync_ctx == ODP_SCHED_SYNC_ATOMIC)
		release_atomic(local);
	else if (local->sync_ctx == ODP_SCHED_SYNC_ORDERED)
		release_ordered(local);

	if (odp_unlikely(local->pause))
		return 0;

	/* TODO: logic incompatible with process-mode applications. Probably
	 *       need to have process-mode-specific scheduler functions. */
	slot->evs         = evs;
	slot->num_max     = num;
	slot->deadline_ns = deadline;

	odp_atomic_store_u32(&slot->state, SLOT_REQUEST);
	notify_service(slot->service_idx, local->thr);
	_odp_wait_until_equal_acq_u32(&slot->state, SLOT_DONE);
	odp_atomic_store_u32(&slot->state, SLOT_IDLE);

	if (out_queue && slot->num_got > 0)
		*out_queue = slot->from;

	return slot->num_got;
}

static odp_event_t schedule(odp_queue_t *out_queue, uint64_t wait)
{
	odp_event_t ev = ODP_EVENT_INVALID;

	(void)worker_request(out_queue, &ev, 1, deadline_from_wait(wait));

	return ev;
}

static int schedule_multi(odp_queue_t *out_queue, uint64_t wait,
			  odp_event_t events[], int num)
{
	return worker_request(out_queue, events, num, deadline_from_wait(wait));
}

static int schedule_multi_no_wait(odp_queue_t *out_queue, odp_event_t events[], int num)
{
	return worker_request(out_queue, events, num, ODP_SCHED_NO_WAIT);
}

static int schedule_multi_wait(odp_queue_t *out_queue, odp_event_t events[], int num)
{
	return worker_request(out_queue, events, num, ODP_SCHED_WAIT);
}

static void schedule_pause(void)
{
	worker_slot[odp_thread_id()].local.pause = 1;
}

static void schedule_resume(void)
{
	worker_slot[odp_thread_id()].local.pause = 0;
}

static uint64_t schedule_wait_time(uint64_t ns)
{
	return ns;
}

/* ---------------------- order locks ---------------------- */

static inline void order_lock(void)
{
	sched_local_t *local = &worker_slot[odp_thread_id()].local;

	if (local->sync_ctx != ODP_SCHED_SYNC_ORDERED)
		return;

	wait_for_order(local->ordered.src_queue, local);
}

static void order_unlock(void)
{
	/* Nothing to do */
}

static void schedule_order_lock(uint32_t lock_index)
{
	sched_local_t *local = &worker_slot[odp_thread_id()].local;
	odp_atomic_u64_t *ord_lock;
	uint32_t qi;

	if (local->sync_ctx != ODP_SCHED_SYNC_ORDERED)
		return;

	qi = local->ordered.src_queue;
	_ODP_ASSERT(lock_index < sched->queue[qi].order_lock_count &&
		    !local->ordered.lock_called.u8[lock_index]);
	ord_lock = &sched->order[qi].lock[lock_index];

	while (1) {
		uint64_t lock_seq = odp_atomic_load_acq_u64(ord_lock);

		if (lock_seq == local->ordered.ctx) {
			local->ordered.lock_called.u8[lock_index] = 1;
			return;
		}

		odp_cpu_pause();
	}
}

static void schedule_order_unlock(uint32_t lock_index)
{
	sched_local_t *local = &worker_slot[odp_thread_id()].local;
	odp_atomic_u64_t *ord_lock;
	uint32_t qi;

	if (local->sync_ctx != ODP_SCHED_SYNC_ORDERED)
		return;

	qi = local->ordered.src_queue;
	_ODP_ASSERT(lock_index < sched->queue[qi].order_lock_count);
	ord_lock = &sched->order[qi].lock[lock_index];
	_ODP_ASSERT(local->ordered.ctx == odp_atomic_load_u64(ord_lock));
	odp_atomic_store_rel_u64(ord_lock, local->ordered.ctx + 1);
}

static void schedule_order_unlock_lock(uint32_t unlock_index, uint32_t lock_index)
{
	schedule_order_unlock(unlock_index);
	schedule_order_lock(lock_index);
}

static void schedule_order_lock_start(uint32_t lock_index ODP_UNUSED)
{
}

static void schedule_order_lock_wait(uint32_t lock_index)
{
	schedule_order_lock(lock_index);
}

static void schedule_prefetch(int num ODP_UNUSED)
{
}

/* ---------------------- groups ---------------------- */

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

static void set_group_prios(odp_schedule_group_t group,
			    const odp_schedule_group_param_t *param)
{
	if (param->prio.num == 0)
		return;

	for (uint32_t i = 0; i < param->prio.num; i++)
		sched->sched_grp[group].level[i] = param->prio.level[i];

	sched->sched_grp[group].num_prio = param->prio.num;
}

static void schedule_group_clear(odp_schedule_group_t group)
{
	odp_thrmask_t zero;

	if (group < 0 || group > ODP_SCHED_GROUP_CONTROL)
		_ODP_ABORT("Invalid scheduling group\n");

	odp_thrmask_zero(&zero);
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

	if (config->sched_group.all)
		num += config->sched_group.all_param.prio.num > 0 ?
			config->sched_group.all_param.prio.num : def;

	if (config->sched_group.control)
		num += config->sched_group.control_param.prio.num > 0 ?
			config->sched_group.control_param.prio.num : def;

	if (config->sched_group.worker)
		num += config->sched_group.worker_param.prio.num > 0 ?
			config->sched_group.worker_param.prio.num : def;

	return num;
}

static odp_schedule_group_t allocate_group(const char *name,
					   const odp_thrmask_t *mask,
					   uint32_t num_prio)
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

	for (int i = SCHED_GROUP_NAMED; i < NUM_GRP; i++) {
		if (!sched->sched_grp[i].allocated) {
			char *grp_name = sched->sched_grp[i].name;

			if (name == NULL)
				grp_name[0] = 0;
			else
				_odp_strcpy(grp_name, name, ODP_SCHED_GROUP_NAME_LEN);

			grp_update_mask(i, mask);
			group = (odp_schedule_group_t)i;
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

	odp_ticketlock_lock(&sched->grp_lock);
	group = allocate_group(name, mask, sched->config_if.max_prios);
	odp_ticketlock_unlock(&sched->grp_lock);

	return group;
}

static odp_schedule_group_t schedule_group_create_2(const char *name,
						    const odp_thrmask_t *mask,
						    const odp_schedule_group_param_t *param)
{
	odp_schedule_group_t group;

	if (!check_group_prios(param, sched->config_if.min_prio, sched->config_if.max_prio)) {
		_ODP_ERR("Bad priority range\n");
		return ODP_SCHED_GROUP_INVALID;
	}

	odp_ticketlock_lock(&sched->grp_lock);
	group = allocate_group(name, mask,
			       param->prio.num > 0 ? param->prio.num
						   : sched->config_if.max_prios);

	if (group != ODP_SCHED_GROUP_INVALID)
		set_group_prios(group, param);

	odp_ticketlock_unlock(&sched->grp_lock);

	return group;
}

static int schedule_group_destroy(odp_schedule_group_t group)
{
	odp_thrmask_t zero;

	if (group >= NUM_GRP || group < SCHED_GROUP_NAMED) {
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

	odp_ticketlock_lock(&sched->grp_lock);

	for (int i = SCHED_GROUP_NAMED; i < NUM_GRP; i++) {
		if (sched->sched_grp[i].allocated &&
		    strcmp(name, sched->sched_grp[i].name) == 0) {
			group = (odp_schedule_group_t)i;
			break;
		}
	}

	odp_ticketlock_unlock(&sched->grp_lock);

	return group;
}

static int schedule_group_join(odp_schedule_group_t group, const odp_thrmask_t *mask)
{
	odp_thrmask_t new_mask;

	if (group >= NUM_GRP || group < SCHED_GROUP_NAMED) {
		_ODP_ERR("Bad group %i\n", group);
		return -1;
	}

	odp_ticketlock_lock(&sched->grp_lock);

	if (sched->sched_grp[group].allocated == 0) {
		odp_ticketlock_unlock(&sched->grp_lock);
		_ODP_ERR("Bad group status\n");
		return -1;
	}

	odp_thrmask_or(&new_mask, &sched->sched_grp[group].mask, mask);
	grp_update_mask(group, &new_mask);
	odp_ticketlock_unlock(&sched->grp_lock);

	return 0;
}

static int schedule_group_leave(odp_schedule_group_t group, const odp_thrmask_t *mask)
{
	odp_thrmask_t new_mask;

	if (group >= NUM_GRP || group < SCHED_GROUP_NAMED) {
		_ODP_ERR("Bad group %i\n", group);
		return -1;
	}

	odp_thrmask_xor(&new_mask, mask, &sched->mask_all);

	odp_ticketlock_lock(&sched->grp_lock);

	if (sched->sched_grp[group].allocated == 0) {
		odp_ticketlock_unlock(&sched->grp_lock);
		_ODP_ERR("Bad group status\n");
		return -1;
	}

	odp_thrmask_and(&new_mask, &sched->sched_grp[group].mask, &new_mask);
	grp_update_mask(group, &new_mask);
	odp_ticketlock_unlock(&sched->grp_lock);

	return 0;
}

static int schedule_group_thrmask(odp_schedule_group_t group, odp_thrmask_t *thrmask)
{
	int ret = -1;

	odp_ticketlock_lock(&sched->grp_lock);

	if (group < NUM_GRP && sched->sched_grp[group].allocated) {
		*thrmask = sched->sched_grp[group].mask;
		ret = 0;
	}

	odp_ticketlock_unlock(&sched->grp_lock);

	return ret;
}

static int schedule_group_info(odp_schedule_group_t group,
			       odp_schedule_group_info_t *info)
{
	int ret = -1;

	odp_ticketlock_lock(&sched->grp_lock);

	if (group < NUM_GRP && sched->sched_grp[group].allocated) {
		info->name    = sched->sched_grp[group].name;
		info->thrmask = sched->sched_grp[group].mask;
		info->num     = sched->sched_grp[group].num_prio;

		for (int i = 0; i < info->num; i++)
			info->level[i] = sched->sched_grp[group].level[i];

		ret = 0;
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
	grp_update_mask(group, &new_mask);
	odp_ticketlock_unlock(&sched->grp_lock);

	return 0;
}

/* ---------------------- config / capability ---------------------- */

static void schedule_config_init(odp_schedule_config_t *config)
{
	config->num_groups      = sched->config_if.max_groups;
	config->num_group_prios = sched->config_if.max_group_prios;
	config->prio.min        = sched->config_if.min_prio;
	config->prio.num        = sched->config_if.max_prios;
	config->num_queues      = sched->max_queues;
	config->queue_size      = _odp_queue_glb->config.max_queue_size;
	config->sched_group.all     = sched->config_if.group_enable.all;
	config->sched_group.control = sched->config_if.group_enable.control;
	config->sched_group.worker  = sched->config_if.group_enable.worker;
}

static int schedule_config(const odp_schedule_config_t *config)
{
	const int max_prio = config->prio.min + config->prio.num - 1;
	const uint32_t inc_grps = get_inc_groups(config);
	const uint32_t inc_grp_prios = get_inc_group_prios(config);

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

	if (start_service_threads()) {
		_ODP_ERR("Failed to start schedule service threads\n");
		return -1;
	}

	odp_ticketlock_lock(&sched->grp_lock);
	sched->config_if.group_enable.all     = config->sched_group.all;
	sched->config_if.group_enable.control = config->sched_group.control;
	sched->config_if.group_enable.worker  = config->sched_group.worker;
	sched->config_if.max_groups      = config->num_groups;
	sched->config_if.max_group_prios = config->num_group_prios;
	sched->config_if.max_prios       = config->prio.num;
	sched->config_if.min_prio        = config->prio.min;
	sched->config_if.max_prio        = max_prio;
	sched->config_if.def_prio = (sched->config_if.max_prio - sched->config_if.min_prio) / 2 +
				    sched->config_if.min_prio;

	for (int i = 0; i < NUM_GRP; i++) {
		for (uint32_t j = 0; j < sched->config_if.max_prios; j++)
			sched->sched_grp[i].level[j] = sched->config_if.min_prio + j;

		sched->sched_grp[i].num_prio = sched->config_if.max_prios;
	}

	set_group_prios(ODP_SCHED_GROUP_ALL, &config->sched_group.all_param);
	set_group_prios(ODP_SCHED_GROUP_WORKER, &config->sched_group.worker_param);
	set_group_prios(ODP_SCHED_GROUP_CONTROL, &config->sched_group.control_param);

	if (!config->sched_group.all)
		schedule_group_clear(ODP_SCHED_GROUP_ALL);

	if (!config->sched_group.worker)
		schedule_group_clear(ODP_SCHED_GROUP_WORKER);

	if (!config->sched_group.control)
		schedule_group_clear(ODP_SCHED_GROUP_CONTROL);

	sched->num_grps      += inc_grps;
	sched->num_grp_prios += inc_grp_prios;

	odp_ticketlock_unlock(&sched->grp_lock);

	return 0;
}

static void schedule_get_config(schedule_config_t *config)
{
	*config = sched->config_if;
}

static int schedule_capability(odp_schedule_capability_t *capa)
{
	memset(capa, 0, sizeof(*capa));
	capa->max_ordered_locks = schedule_max_ordered_locks();
	capa->max_groups        = sched->config_if.max_groups;
	capa->max_group_prios   = sched->config_if.max_group_prios;
	capa->min_prio          = sched->config_if.min_prio;
	capa->max_prios         = sched->config_if.max_prios;
	capa->max_queues        = sched->max_queues;
	capa->max_queue_size    = _odp_queue_glb->config.max_queue_size;
	capa->max_flow_id       = BUF_HDR_MAX_FLOW_ID;
	capa->order_wait        = ODP_SUPPORT_YES;

	return 0;
}

static void schedule_print(void)
{
	_ODP_PRINT("\nScheduler debug info\n");
	_ODP_PRINT("--------------------\n");
	_ODP_PRINT("  scheduler:         centralized\n");
	_ODP_PRINT("  max groups:        %u\n", sched->config_if.max_groups);
	_ODP_PRINT("  max priorities:    %u\n", sched->config_if.max_prios);
	_ODP_PRINT("  service threads:   %u\n", sched->svc.num_threads);

	_ODP_PRINT("\n  Ready masks per priority:\n");
	for (int p = 0; p < NUM_PRIO; p++) {
		uint64_t m = mask_load(p);

		if (m)
			_ODP_PRINT("    prio %d: 0x%016" PRIx64 "\n", p, m);
	}

	_ODP_PRINT("\n  Groups:\n");
	for (int g = 0; g < NUM_GRP; g++) {
		if (sched->sched_grp[g].allocated)
			_ODP_PRINT("    group %i: %s\n", g, sched->sched_grp[g].name);
	}
	_ODP_PRINT("\n");
}

/* ---------------------- vtable ---------------------- */

const _odp_schedule_api_fn_t _odp_schedule_centralized_api;

static const _odp_schedule_api_fn_t *sched_api(void)
{
	return &_odp_schedule_centralized_api;
}

schedule_fn_t _odp_schedule_centralized_fn = {
	.pktio_start    = schedule_pktio_start,
	.thr_add        = schedule_thr_add,
	.thr_rem        = schedule_thr_rem,
	.create_queue   = schedule_create_queue,
	.destroy_queue  = schedule_destroy_queue,
	.sched_queue    = schedule_sched_queue,
	.ord_enq_multi  = schedule_ord_enq_multi,
	.ord_stash_release = schedule_ord_stash_release,
	.init_global    = schedule_init_global,
	.term_global    = schedule_term_global,
	.init_local     = schedule_init_local,
	.term_local     = schedule_term_local,
	.order_lock     = order_lock,
	.order_unlock   = order_unlock,
	.max_ordered_locks = schedule_max_ordered_locks,
	.get_config     = schedule_get_config,
	.sched_api      = sched_api,
};

const _odp_schedule_api_fn_t _odp_schedule_centralized_api = {
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
