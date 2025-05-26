/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2019-2025 Nokia
 */

/*
 * Suppress bounds warnings about interior zero length arrays. Such an array
 * is used intentionally in prio_queue_t.
 */
#if __GNUC__ >= 10
#pragma GCC diagnostic ignored "-Wzero-length-bounds"
#endif

#include <odp/api/packet.h>
#include <odp/api/ticketlock.h>
#include <odp/api/thread.h>
#include <odp/api/plat/thread_inlines.h>
#include <odp/api/time.h>
#include <odp/api/plat/time_inlines.h>
#include <odp/api/schedule.h>
#include <odp/api/shared_memory.h>

#include <odp/api/plat/schedule_inline_types.h>

#include <odp_schedule_if.h>
#include <odp_debug_internal.h>
#include <odp_config_internal.h>
#include <odp_event_internal.h>
#include <odp_macros_internal.h>
#include <odp_ring_mpmc_rst_u32_internal.h>
#include <odp_timer_internal.h>
#include <odp_queue_basic_internal.h>
#include <odp_string_internal.h>
#include <odp_global_data.h>

#include <stddef.h>
#include <string.h>

#define NUM_THREAD        ODP_THREAD_COUNT_MAX
#define NUM_QUEUE         CONFIG_MAX_SCHED_QUEUES
#define NUM_PKTIO         CONFIG_PKTIO_ENTRIES
#define NUM_ORDERED_LOCKS 1
#define NUM_STATIC_GROUP  3
#define NUM_GROUP         (NUM_STATIC_GROUP + 9)
#define NUM_PKTIN         32
#define NUM_PRIO          3
#define MAX_API_PRIO      (NUM_PRIO - 2)
/* Lowest internal priority */
#define PKTIN_PRIO        (NUM_PRIO - 1)
#define CMD_QUEUE         0
#define CMD_PKTIO         1
#define GROUP_ALL         ODP_SCHED_GROUP_ALL
#define GROUP_WORKER      ODP_SCHED_GROUP_WORKER
#define GROUP_CONTROL     ODP_SCHED_GROUP_CONTROL
#define GROUP_PKTIN       GROUP_ALL

/* Maximum number of commands: one priority/group for all queues and pktios */
#define RING_SIZE         (_ODP_ROUNDUP_POWER2_U32(NUM_QUEUE + NUM_PKTIO))
#define RING_MASK         (RING_SIZE - 1)

/* Ring size must be power of two */
ODP_STATIC_ASSERT(_ODP_CHECK_IS_POWER2(RING_SIZE),
		  "Ring_size_is_not_power_of_two");

ODP_STATIC_ASSERT(NUM_ORDERED_LOCKS <= CONFIG_QUEUE_MAX_ORD_LOCKS,
		  "Too_many_ordered_locks");

typedef struct ODP_ALIGNED_CACHE {
	uint32_t           index;
	uint32_t           ring_idx;
	int                type;
	int                prio;
	int                group;
	int                init;
	int                num_pktin;
	int                pktin_idx[NUM_PKTIN];
	odp_queue_t        queue[NUM_PKTIN];
} sched_cmd_t;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
typedef struct ODP_ALIGNED_CACHE {
	/* Ring header */
	ring_mpmc_rst_u32_t ring;

	/* Ring data: queue indexes */
	uint32_t ring_idx[RING_SIZE]; /* overlaps with ring.data[] */

} prio_queue_t;
#pragma GCC diagnostic pop

typedef struct thr_group_t {
	/* A generation counter for fast comparison if groups have changed */
	odp_atomic_u32_t gen_cnt;

	/* Number of groups the thread belongs to */
	int num_group;

	/* The groups the thread belongs to */
	int group[NUM_GROUP];

} thr_group_t;

typedef struct ODP_ALIGNED_CACHE sched_group_t {
	struct {
		odp_ticketlock_t  lock;

		/* All groups */
		struct {
			char          name[ODP_SCHED_GROUP_NAME_LEN];
			odp_thrmask_t mask;
			int           allocated;
			uint8_t       level[NUM_PRIO];
			uint32_t      num_prio;
		} group[NUM_GROUP];

		/* Per thread group information */
		thr_group_t thr[NUM_THREAD];

	} s;

} sched_group_t;

typedef struct {
	sched_cmd_t   queue_cmd[NUM_QUEUE];
	sched_cmd_t   pktio_cmd[NUM_PKTIO];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	prio_queue_t  prio_queue[NUM_GROUP][NUM_PRIO];
#pragma GCC diagnostic pop
	sched_group_t sched_group;
	odp_shm_t     shm;
	/* Scheduler interface config options (not used in fast path) */
	schedule_config_t config_if;
	uint32_t num_grps;
	uint32_t num_grp_prios;
} sched_global_t;

typedef struct {
	sched_cmd_t *cmd;
	int          pause;
	int          thr_id;
	uint32_t     gen_cnt;
	int          num_group;
	int          group[NUM_GROUP];
} sched_local_t;

static sched_global_t *sched_global;
static __thread sched_local_t sched_local;

static void remove_group(sched_group_t *sched_group, int thr, int group);

static inline uint32_t index_to_ring_idx(int pktio, uint32_t index)
{
	if (pktio)
		return (0x80000000 | index);

	return index;
}

static inline uint32_t index_from_ring_idx(uint32_t *index, uint32_t ring_idx)
{
	uint32_t pktio = ring_idx & 0x80000000;

	if (pktio)
		*index = ring_idx & (~0x80000000);
	else
		*index = ring_idx;

	return pktio;
}

static int init_global(void)
{
	int i, j;
	odp_shm_t shm;
	sched_group_t *sched_group = NULL;

	_ODP_DBG("Using SP scheduler\n");

	shm = odp_shm_reserve("_odp_sched_sp_global",
			      sizeof(sched_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	sched_global = odp_shm_addr(shm);

	if (sched_global == NULL) {
		_ODP_ERR("Schedule init: Shm reserve failed.\n");
		return -1;
	}

	memset(sched_global, 0, sizeof(sched_global_t));
	sched_global->shm = shm;

	for (i = 0; i < NUM_QUEUE; i++) {
		sched_global->queue_cmd[i].type     = CMD_QUEUE;
		sched_global->queue_cmd[i].index    = i;
		sched_global->queue_cmd[i].ring_idx = index_to_ring_idx(0, i);
	}

	for (i = 0; i < NUM_PKTIO; i++) {
		sched_global->pktio_cmd[i].type     = CMD_PKTIO;
		sched_global->pktio_cmd[i].index    = i;
		sched_global->pktio_cmd[i].ring_idx = index_to_ring_idx(1, i);
		sched_global->pktio_cmd[i].prio     = PKTIN_PRIO;
		sched_global->pktio_cmd[i].group    = GROUP_PKTIN;
	}

	for (i = 0; i < NUM_GROUP; i++)
		for (j = 0; j < NUM_PRIO; j++)
			ring_mpmc_rst_u32_init(&sched_global->prio_queue[i][j].ring);

	sched_group = &sched_global->sched_group;
	odp_ticketlock_init(&sched_group->s.lock);

	for (i = 0; i < NUM_THREAD; i++)
		odp_atomic_init_u32(&sched_group->s.thr[i].gen_cnt, 0);

	_odp_strcpy(sched_group->s.group[GROUP_ALL].name, "__group_all",
		    ODP_SCHED_GROUP_NAME_LEN);
	odp_thrmask_zero(&sched_group->s.group[GROUP_ALL].mask);
	sched_group->s.group[GROUP_ALL].allocated = 1;

	_odp_strcpy(sched_group->s.group[GROUP_WORKER].name, "__group_worker",
		    ODP_SCHED_GROUP_NAME_LEN);
	odp_thrmask_zero(&sched_group->s.group[GROUP_WORKER].mask);
	sched_group->s.group[GROUP_WORKER].allocated = 1;

	_odp_strcpy(sched_group->s.group[GROUP_CONTROL].name, "__group_control",
		    ODP_SCHED_GROUP_NAME_LEN);
	odp_thrmask_zero(&sched_group->s.group[GROUP_CONTROL].mask);
	sched_group->s.group[GROUP_CONTROL].allocated = 1;

	sched_global->config_if.group_enable.all = 1;
	sched_global->config_if.group_enable.control = 1;
	sched_global->config_if.group_enable.worker = 1;
	sched_global->config_if.max_groups = NUM_GROUP - NUM_STATIC_GROUP;
	sched_global->config_if.max_group_prios = NUM_GROUP * NUM_PRIO;
	/* Lowest priority is used for pktin polling and is internal to the scheduler */
	sched_global->config_if.max_prios = NUM_PRIO - 1;
	sched_global->config_if.min_prio = 0;
	sched_global->config_if.max_prio = MAX_API_PRIO;
	sched_global->config_if.def_prio = sched_global->config_if.max_prio / 2;

	for (i = 0; i < NUM_GROUP; i++) {
		for (j = 0; j < (int)sched_global->config_if.max_prios; ++j)
			sched_group->s.group[i].level[j] = sched_global->config_if.min_prio + j;

		sched_group->s.group[i].num_prio = sched_global->config_if.max_prios;
	}

	return 0;
}

static int init_local(void)
{
	memset(&sched_local, 0, sizeof(sched_local_t));
	sched_local.thr_id = odp_thread_id();

	return 0;
}

static int term_global(void)
{
	odp_event_t event;
	int qi, ret = 0;

	for (qi = 0; qi < NUM_QUEUE; qi++) {
		int report = 1;

		if (sched_global->queue_cmd[qi].init) {
			while (_odp_sched_queue_deq(qi, &event, 1, 1) > 0) {
				if (report) {
					_ODP_ERR("Queue not empty\n");
					report = 0;
				}
				odp_event_free(event);
			}
		}
	}

	ret = odp_shm_free(sched_global->shm);
	if (ret < 0) {
		_ODP_ERR("Shm free failed for sp_scheduler");
		ret = -1;
	}

	return ret;
}

static int term_local(void)
{
	return 0;
}

static void schedule_config_init(odp_schedule_config_t *config)
{
	config->num_groups = sched_global->config_if.max_groups;
	config->num_group_prios = sched_global->config_if.max_group_prios;
	config->prio.min = sched_global->config_if.min_prio;
	config->prio.num = sched_global->config_if.max_prios;
	config->num_queues = CONFIG_MAX_SCHED_QUEUES;
	config->queue_size = _odp_queue_glb->config.max_queue_size;
	config->sched_group.all = true;
	config->sched_group.control = true;
	config->sched_group.worker = true;
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
		sched_global->sched_group.s.group[group].level[i] = param->prio.level[i];

	sched_global->sched_group.s.group[group].num_prio = param->prio.num;
}

static void schedule_group_clear(odp_schedule_group_t group)
{
	sched_group_t *sched_group = &sched_global->sched_group;
	int thr;
	const odp_thrmask_t *thrmask;

	if (group < 0 || group >= NUM_STATIC_GROUP)
		_ODP_ABORT("Invalid scheduling group\n");

	thrmask = &sched_group->s.group[group].mask;

	thr = odp_thrmask_first(thrmask);
	while (thr >= 0) {
		remove_group(sched_group, thr, group);
		thr = odp_thrmask_next(thrmask, thr);
	}

	sched_group->s.group[group].allocated = 0;
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
	sched_group_t *sched_group = &sched_global->sched_group;

	if (config->num_groups > sched_global->config_if.max_groups) {
		_ODP_ERR("Bad number of groups %u\n", config->num_groups);
		return -1;
	}

	if (config->num_group_prios > sched_global->config_if.max_group_prios) {
		_ODP_ERR("Bad number of group priorities %u\n", config->num_group_prios);
		return -1;
	}

	if (config->prio.num > sched_global->config_if.max_prios) {
		_ODP_ERR("Bad number of priorities %u\n", config->prio.num);
		return -1;
	}

	if (config->prio.min < sched_global->config_if.min_prio) {
		_ODP_ERR("Bad minimum priority %u\n", config->prio.min);
		return -1;
	}

	if (max_prio > sched_global->config_if.max_prio) {
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

	odp_ticketlock_lock(&sched_group->s.lock);
	sched_global->config_if.group_enable.all = config->sched_group.all;
	sched_global->config_if.group_enable.control = config->sched_group.control;
	sched_global->config_if.group_enable.worker = config->sched_group.worker;
	sched_global->config_if.max_groups = config->num_groups;
	sched_global->config_if.max_group_prios = config->num_group_prios;
	sched_global->config_if.max_prios = config->prio.num;
	sched_global->config_if.min_prio = config->prio.min;
	sched_global->config_if.max_prio = max_prio;
	sched_global->config_if.def_prio = (sched_global->config_if.max_prio -
					    sched_global->config_if.min_prio) / 2 +
					   sched_global->config_if.min_prio;

	for (int i = 0; i < NUM_GROUP; i++) {
		for (uint32_t j = 0; j < sched_global->config_if.max_prios; ++j)
			sched_group->s.group[i].level[j] = sched_global->config_if.min_prio + j;

		sched_group->s.group[i].num_prio = sched_global->config_if.max_prios;
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

	sched_global->num_grps += inc_grps;
	sched_global->num_grp_prios += inc_grp_prios;

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static uint32_t max_ordered_locks(void)
{
	return NUM_ORDERED_LOCKS;
}

static void add_group(sched_group_t *sched_group, int thr, int group)
{
	int num;
	uint32_t gen_cnt;
	thr_group_t *thr_group = &sched_group->s.thr[thr];

	num = thr_group->num_group;
	thr_group->group[num] = group;
	thr_group->num_group  = num + 1;
	gen_cnt = odp_atomic_load_u32(&thr_group->gen_cnt);
	odp_atomic_store_rel_u32(&thr_group->gen_cnt, gen_cnt + 1);
}

static void remove_group(sched_group_t *sched_group, int thr, int group)
{
	int i, num;
	int found = 0;
	thr_group_t *thr_group = &sched_group->s.thr[thr];

	num = thr_group->num_group;

	/* Extra array bounds check to suppress warning on GCC 7.4 with -O3 */
	if (num >= NUM_GROUP) {
		_ODP_ERR("Too many groups");
		return;
	}

	for (i = 0; i < num; i++) {
		if (thr_group->group[i] == group) {
			found = 1;

			for (; i < num - 1; i++)
				thr_group->group[i] = thr_group->group[i + 1];

			break;
		}
	}

	if (found) {
		uint32_t gen_cnt;

		thr_group->num_group = num - 1;
		gen_cnt = odp_atomic_load_u32(&thr_group->gen_cnt);
		odp_atomic_store_rel_u32(&thr_group->gen_cnt, gen_cnt + 1);
	}
}

static int thr_add(odp_schedule_group_t group, int thr)
{
	sched_group_t *sched_group = &sched_global->sched_group;

	if (group < 0 || group >= NUM_STATIC_GROUP)
		return -1;

	if (thr < 0 || thr >= NUM_THREAD)
		return -1;

	odp_ticketlock_lock(&sched_group->s.lock);

	if (!sched_group->s.group[group].allocated) {
		odp_ticketlock_unlock(&sched_group->s.lock);
		return 0;
	}

	odp_thrmask_set(&sched_group->s.group[group].mask, thr);
	add_group(sched_group, thr, group);

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static int thr_rem(odp_schedule_group_t group, int thr)
{
	sched_group_t *sched_group = &sched_global->sched_group;

	if (group < 0 || group >= NUM_STATIC_GROUP)
		return -1;

	odp_ticketlock_lock(&sched_group->s.lock);

	if (!sched_group->s.group[group].allocated) {
		odp_ticketlock_unlock(&sched_group->s.lock);
		return 0;
	}

	odp_thrmask_clr(&sched_group->s.group[group].mask, thr);

	remove_group(sched_group, thr, group);

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static int check_queue_prio(int prio, int grp)
{
	for (uint32_t i = 0; i < sched_global->sched_group.s.group[grp].num_prio; i++)
		if (prio == sched_global->sched_group.s.group[grp].level[i])
			return 1;

	return 0;
}

static int create_queue(uint32_t qi, const odp_schedule_param_t *sched_param)
{
	sched_group_t *sched_group = &sched_global->sched_group;
	odp_schedule_group_t group = sched_param->group;
	int prio = 0;

	if (odp_global_rw->schedule_configured == 0) {
		_ODP_ERR("Scheduler has not been configured\n");
		return -1;
	}

	if (group < 0 || group >= NUM_GROUP)
		return -1;

	if (!sched_group->s.group[group].allocated)
		return -1;

	if (!check_queue_prio(sched_param->prio, group)) {
		_ODP_ERR("Bad priority %i\n", sched_param->prio);
		return -1;
	}

	/* Inverted prio value (max = 0) vs API */
	prio = MAX_API_PRIO - sched_param->prio;

	sched_global->queue_cmd[qi].prio  = prio;
	sched_global->queue_cmd[qi].group = group;
	sched_global->queue_cmd[qi].init  = 1;

	return 0;
}

static void destroy_queue(uint32_t qi)
{
	sched_global->queue_cmd[qi].prio  = 0;
	sched_global->queue_cmd[qi].group = 0;
	sched_global->queue_cmd[qi].init  = 0;
}

static inline void add_tail(sched_cmd_t *cmd)
{
	prio_queue_t *prio_queue;
	int group    = cmd->group;
	int prio     = cmd->prio;
	uint32_t idx = cmd->ring_idx;

	prio_queue = &sched_global->prio_queue[group][prio];
	ring_mpmc_rst_u32_enq(&prio_queue->ring, RING_MASK, idx);
}

static inline sched_cmd_t *rem_head(int group, int prio)
{
	prio_queue_t *prio_queue;
	uint32_t ring_idx, index;
	int pktio;

	prio_queue = &sched_global->prio_queue[group][prio];

	if (ring_mpmc_rst_u32_deq(&prio_queue->ring, RING_MASK, &ring_idx) == 0)
		return NULL;

	pktio = index_from_ring_idx(&index, ring_idx);

	if (pktio)
		return &sched_global->pktio_cmd[index];

	return &sched_global->queue_cmd[index];
}

static int sched_queue(uint32_t qi)
{
	sched_cmd_t *cmd;

	cmd = &sched_global->queue_cmd[qi];
	add_tail(cmd);

	return 0;
}

static int ord_enq_multi(odp_queue_t queue, void *buf_hdr[], int num,
			 int *ret)
{
	(void)queue;
	(void)buf_hdr;
	(void)num;
	(void)ret;

	/* didn't consume the events */
	return 0;
}

static void ord_stash_release(odp_queue_t queue ODP_UNUSED)
{
	/* Nothing to do */
}

static void pktio_start(int pktio_index,
			int num,
			int pktin_idx[],
			odp_queue_t queue[])
{
	int i;
	sched_cmd_t *cmd;

	_ODP_DBG("pktio index: %i, %i pktin queues %i\n", pktio_index, num, pktin_idx[0]);

	cmd = &sched_global->pktio_cmd[pktio_index];

	if (num > NUM_PKTIN)
		_ODP_ABORT("Supports only %i pktin queues per interface\n", NUM_PKTIN);

	for (i = 0; i < num; i++) {
		cmd->pktin_idx[i] = pktin_idx[i];
		cmd->queue[i]     = queue[i];
	}

	cmd->num_pktin = num;

	add_tail(cmd);
}

static inline sched_cmd_t *sched_cmd(void)
{
	int prio, i;
	int thr = sched_local.thr_id;
	sched_group_t *sched_group = &sched_global->sched_group;
	thr_group_t *thr_group = &sched_group->s.thr[thr];
	uint32_t gen_cnt;

	/* There's no matching store_rel since the value is updated while
	 * holding a lock */
	gen_cnt = odp_atomic_load_acq_u32(&thr_group->gen_cnt);

	/* Check if groups have changed and need to be read again */
	if (odp_unlikely(gen_cnt != sched_local.gen_cnt)) {
		int num_grp;

		odp_ticketlock_lock(&sched_group->s.lock);

		num_grp = thr_group->num_group;
		gen_cnt = odp_atomic_load_u32(&thr_group->gen_cnt);

		for (i = 0; i < num_grp; i++)
			sched_local.group[i] = thr_group->group[i];

		odp_ticketlock_unlock(&sched_group->s.lock);

		sched_local.num_group = num_grp;
		sched_local.gen_cnt   = gen_cnt;
	}

	for (i = 0; i < sched_local.num_group; i++) {
		for (prio = 0; prio < NUM_PRIO; prio++) {
			sched_cmd_t *cmd = rem_head(sched_local.group[i], prio);

			if (cmd)
				return cmd;
		}
	}

	return NULL;
}

static uint64_t schedule_wait_time(uint64_t ns)
{
	return ns;
}

static inline void enqueue_packets(odp_queue_t queue,
				   _odp_event_hdr_t *hdr_tbl[], int num_pkt)
{
	int num_enq, num_drop;

	num_enq = odp_queue_enq_multi(queue, (odp_event_t *)hdr_tbl,
				      num_pkt);

	if (num_enq < 0)
		num_enq = 0;

	if (num_enq < num_pkt) {
		num_drop = num_pkt - num_enq;

		_ODP_DBG("Dropped %i packets\n", num_drop);
		odp_packet_free_multi((odp_packet_t *)&hdr_tbl[num_enq],
				      num_drop);
	}
}

static int schedule_multi(odp_queue_t *from, uint64_t wait,
			  odp_event_t events[], int max_events ODP_UNUSED)
{
	odp_time_t t1;
	int update_t1 = 1;

	if (sched_local.cmd) {
		/* Continue scheduling if queue is not empty */
		if (_odp_sched_queue_empty(sched_local.cmd->index) == 0)
			add_tail(sched_local.cmd);

		sched_local.cmd = NULL;
	}

	if (odp_unlikely(sched_local.pause))
		return 0;

	while (1) {
		sched_cmd_t *cmd;
		uint32_t qi;
		int num;

		cmd = sched_cmd();

		if (cmd && cmd->type == CMD_PKTIO) {
			_odp_event_hdr_t *hdr_tbl[CONFIG_BURST_SIZE];
			int i;
			int num_pkt = 0;
			int max_num = CONFIG_BURST_SIZE;
			int pktio_idx = cmd->index;
			int num_pktin = cmd->num_pktin;
			int *pktin_idx = cmd->pktin_idx;
			odp_queue_t *queue = cmd->queue;

			for (i = 0; i < num_pktin; i++) {
				num_pkt = _odp_sched_cb_pktin_poll(pktio_idx,
								   pktin_idx[i],
								   hdr_tbl, max_num);

				if (num_pkt < 0) {
					/* Pktio stopped or closed. */
					_odp_sched_cb_pktio_stop_finalize(pktio_idx);
					break;
				}

				if (num_pkt == 0)
					continue;

				enqueue_packets(queue[i], hdr_tbl, num_pkt);
			}

			if (num_pkt >= 0) {
				/* Continue polling pktio. */
				add_tail(cmd);
			}

			/* run wait parameter checks under */
			cmd = NULL;
		}

		if (cmd == NULL) {
			timer_run(1);
			/* All priority queues are empty */
			if (wait == ODP_SCHED_NO_WAIT)
				return 0;

			if (wait == ODP_SCHED_WAIT)
				continue;

			if (update_t1) {
				t1 = odp_time_add_ns(odp_time_local(), wait);
				update_t1 = 0;
				continue;
			}

			if (odp_time_cmp(odp_time_local(), t1) < 0)
				continue;

			return 0;
		}

		qi  = cmd->index;
		num = _odp_sched_queue_deq(qi, events, 1, 1);

		if (num <= 0) {
			timer_run(1);
			/* Destroyed or empty queue. Remove empty queue from
			 * scheduling. A dequeue operation to on an already
			 * empty queue moves it to NOTSCHED state and
			 * sched_queue() will be called on next enqueue. */
			continue;
		}

		timer_run(2);

		sched_local.cmd = cmd;

		if (from)
			*from = queue_from_index(qi);

		return num;
	}
}

static odp_event_t schedule(odp_queue_t *from, uint64_t wait)
{
	odp_event_t ev;

	if (schedule_multi(from, wait, &ev, 1) > 0)
		return ev;

	return ODP_EVENT_INVALID;
}

static int schedule_multi_wait(odp_queue_t *from, odp_event_t events[],
			       int max_num)
{
	return schedule_multi(from, ODP_SCHED_WAIT, events, max_num);
}

static int schedule_multi_no_wait(odp_queue_t *from, odp_event_t events[],
				  int max_num)
{
	return schedule_multi(from, ODP_SCHED_NO_WAIT, events, max_num);
}

static void schedule_pause(void)
{
	sched_local.pause = 1;
}

static void schedule_resume(void)
{
	sched_local.pause = 0;
}

static void schedule_release_atomic(void)
{
	/* Nothing to do */
}

static void schedule_release_ordered(void)
{
	/* Nothing to do */
}

static void schedule_prefetch(int num)
{
	(void)num;
}

static int schedule_min_prio(void)
{
	return sched_global->config_if.min_prio;
}

static int schedule_max_prio(void)
{
	return sched_global->config_if.max_prio;
}

static int schedule_default_prio(void)
{
	return sched_global->config_if.def_prio;
}

static int schedule_num_prio(void)
{
	return sched_global->config_if.max_prios;
}

static odp_schedule_group_t allocate_group(const char *name, const odp_thrmask_t *thrmask,
					   sched_group_t *sched_group, uint32_t num_prio)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	int thr_tbl[NUM_THREAD];
	int thr, num_thr;

	if (sched_global->num_grps >= sched_global->config_if.max_groups) {
		_ODP_ERR("Maximum number of groups created\n");
		return group;
	}

	if (sched_global->num_grp_prios + num_prio > sched_global->config_if.max_group_prios) {
		_ODP_ERR("Insufficient group priorities (attempted: %u, left: %u)\n",
			 num_prio,
			 sched_global->config_if.max_group_prios - sched_global->num_grp_prios);
		return group;
	}

	num_thr = odp_thrmask_count(thrmask);
	if (num_thr < 0 || num_thr > NUM_THREAD) {
		_ODP_ERR("Bad thread count: %d\n", num_thr);
		return group;
	}

	thr = odp_thrmask_first(thrmask);
	num_thr = 0;
	while (thr >= 0 && num_thr < NUM_THREAD) {
		if (thr >= NUM_THREAD) {
			_ODP_ERR("Invalid thread ID: %d, max: %d\n", thr, NUM_THREAD - 1);
			return group;
		}
		thr_tbl[num_thr++] = thr;
		thr = odp_thrmask_next(thrmask, thr);
	}

	for (int i = NUM_STATIC_GROUP; i < NUM_GROUP; i++) {
		if (!sched_group->s.group[i].allocated) {
			char *grp_name = sched_group->s.group[i].name;

			if (name == NULL)
				grp_name[0] = 0;
			else
				_odp_strcpy(grp_name, name,
					    ODP_SCHED_GROUP_NAME_LEN);

			odp_thrmask_copy(&sched_group->s.group[i].mask, thrmask);
			sched_group->s.group[i].allocated = 1;
			sched_global->num_grps++;
			sched_global->num_grp_prios += num_prio;

			group = i;

			for (int j = 0; j < num_thr; j++)
				add_group(sched_group, thr_tbl[j], group);

			break;
		}
	}

	return group;
}

static odp_schedule_group_t schedule_group_create(const char *name,
						  const odp_thrmask_t *thrmask)
{
	odp_schedule_group_t group;
	sched_group_t *sched_group = &sched_global->sched_group;

	odp_ticketlock_lock(&sched_group->s.lock);
	group = allocate_group(name, thrmask, sched_group, sched_global->config_if.max_prios);
	odp_ticketlock_unlock(&sched_group->s.lock);

	return group;
}

static odp_schedule_group_t schedule_group_create_2(const char *name,
						    const odp_thrmask_t *thrmask,
						    const odp_schedule_group_param_t *param)
{
	odp_schedule_group_t group;
	sched_group_t *sched_group = &sched_global->sched_group;

	if (!check_group_prios(param, sched_global->config_if.min_prio,
			       sched_global->config_if.max_prio)) {
		_ODP_ERR("Bad priority range\n");
		return ODP_SCHED_GROUP_INVALID;
	}

	odp_ticketlock_lock(&sched_group->s.lock);
	group = allocate_group(name, thrmask, sched_group,
			       param->prio.num > 0 ?
				param->prio.num : sched_global->config_if.max_prios);

	if (group != ODP_SCHED_GROUP_INVALID)
		set_group_prios(group, param);

	odp_ticketlock_unlock(&sched_group->s.lock);

	return group;
}

static int schedule_group_destroy(odp_schedule_group_t group)
{
	sched_group_t *sched_group = &sched_global->sched_group;
	int thr;
	const odp_thrmask_t *thrmask;

	if (group < NUM_STATIC_GROUP || group >= NUM_GROUP)
		return -1;

	odp_ticketlock_lock(&sched_group->s.lock);

	if (!sched_group->s.group[group].allocated) {
		odp_ticketlock_unlock(&sched_group->s.lock);
		return -1;
	}

	thrmask = &sched_group->s.group[group].mask;

	thr = odp_thrmask_first(thrmask);
	while (thr >= 0) {
		remove_group(sched_group, thr, group);
		thr = odp_thrmask_next(thrmask, thr);
	}

	memset(sched_group->s.group[group].name, 0, ODP_SCHED_GROUP_NAME_LEN);
	sched_group->s.group[group].allocated = 0;
	sched_global->num_grps--;
	sched_global->num_grp_prios -= sched_group->s.group[group].num_prio;

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static odp_schedule_group_t schedule_group_lookup(const char *name)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	sched_group_t *sched_group = &sched_global->sched_group;
	int i;

	odp_ticketlock_lock(&sched_group->s.lock);

	for (i = NUM_STATIC_GROUP; i < NUM_GROUP; i++) {
		if (sched_group->s.group[i].allocated &&
		    strcmp(sched_group->s.group[i].name, name) == 0) {
			group = i;
			break;
		}
	}

	odp_ticketlock_unlock(&sched_group->s.lock);
	return group;
}

static int schedule_group_join(odp_schedule_group_t group,
			       const odp_thrmask_t *thrmask)
{
	int thr;
	sched_group_t *sched_group = &sched_global->sched_group;

	if (group < 0 || group >= NUM_GROUP)
		return -1;

	thr = odp_thrmask_first(thrmask);

	odp_ticketlock_lock(&sched_group->s.lock);

	if (!sched_group->s.group[group].allocated) {
		odp_ticketlock_unlock(&sched_group->s.lock);
		return -1;
	}

	odp_thrmask_or(&sched_group->s.group[group].mask,
		       &sched_group->s.group[group].mask,
		       thrmask);

	while (thr >= 0) {
		add_group(sched_group, thr, group);
		thr = odp_thrmask_next(thrmask, thr);
	}

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static int schedule_group_leave(odp_schedule_group_t group,
				const odp_thrmask_t *thrmask)
{
	int thr;
	sched_group_t *sched_group = &sched_global->sched_group;
	odp_thrmask_t *all = &sched_group->s.group[GROUP_ALL].mask;
	odp_thrmask_t not;

	if (group < 0 || group >= NUM_GROUP)
		return -1;

	thr = odp_thrmask_first(thrmask);

	odp_ticketlock_lock(&sched_group->s.lock);

	if (!sched_group->s.group[group].allocated) {
		odp_ticketlock_unlock(&sched_group->s.lock);
		return -1;
	}

	odp_thrmask_xor(&not, thrmask, all);
	odp_thrmask_and(&sched_group->s.group[group].mask,
			&sched_group->s.group[group].mask,
			&not);

	while (thr >= 0) {
		remove_group(sched_group, thr, group);
		thr = odp_thrmask_next(thrmask, thr);
	}

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static int schedule_group_thrmask(odp_schedule_group_t group,
				  odp_thrmask_t *thrmask)
{
	sched_group_t *sched_group = &sched_global->sched_group;

	if (group < 0 || group >= NUM_GROUP)
		return -1;

	odp_ticketlock_lock(&sched_group->s.lock);

	if (!sched_group->s.group[group].allocated) {
		odp_ticketlock_unlock(&sched_group->s.lock);
		return -1;
	}

	*thrmask = sched_group->s.group[group].mask;

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static int schedule_group_info(odp_schedule_group_t group,
			       odp_schedule_group_info_t *info)
{
	sched_group_t *sched_group = &sched_global->sched_group;

	if (group < 0 || group >= NUM_GROUP)
		return -1;

	odp_ticketlock_lock(&sched_group->s.lock);

	if (!sched_group->s.group[group].allocated) {
		odp_ticketlock_unlock(&sched_group->s.lock);
		return -1;
	}

	info->name    = sched_group->s.group[group].name;
	info->thrmask = sched_group->s.group[group].mask;
	info->num     = sched_group->s.group[group].num_prio;

	for (int i = 0; i < info->num; i++)
		info->level[i] = sched_group->s.group[group].level[i];

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static void schedule_order_lock(uint32_t lock_index)
{
	(void)lock_index;
}

static void schedule_order_unlock(uint32_t lock_index)
{
	(void)lock_index;
}

static void schedule_order_unlock_lock(uint32_t unlock_index,
				       uint32_t lock_index)
{
	(void)unlock_index;
	(void)lock_index;
}

static void schedule_order_lock_start(uint32_t lock_index)
{
	(void)lock_index;
}

static void schedule_order_lock_wait(uint32_t lock_index)
{
	(void)lock_index;
}

static void order_lock(void)
{
	/* Nothing to do */
}

static void order_unlock(void)
{
	/* Nothing to do */
}

static int schedule_capability(odp_schedule_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_schedule_capability_t));

	capa->max_ordered_locks = max_ordered_locks();
	capa->max_groups = sched_global->config_if.max_groups;
	capa->max_group_prios = sched_global->config_if.max_group_prios;
	capa->min_prio = sched_global->config_if.min_prio;
	capa->max_prios = sched_global->config_if.max_prios;
	capa->max_queues = CONFIG_MAX_SCHED_QUEUES;
	capa->max_queue_size = _odp_queue_glb->config.max_queue_size;

	return 0;
}

static void schedule_print(void)
{
	odp_schedule_capability_t capa;

	(void)schedule_capability(&capa);

	_ODP_PRINT("\nScheduler debug info\n");
	_ODP_PRINT("--------------------\n");
	_ODP_PRINT("  scheduler:         sp\n");
	_ODP_PRINT("  max groups:        %u\n", capa.max_groups);
	_ODP_PRINT("  max priorities:    %u\n", capa.max_prios);
	_ODP_PRINT("\n");
}

static void get_config(schedule_config_t *config)
{
	*config = sched_global->config_if;
}

const _odp_schedule_api_fn_t _odp_schedule_sp_api;

static const _odp_schedule_api_fn_t *sched_api(void)
{
	return &_odp_schedule_sp_api;
}

/* Fill in scheduler interface */
const schedule_fn_t _odp_schedule_sp_fn = {
	.pktio_start   = pktio_start,
	.thr_add       = thr_add,
	.thr_rem       = thr_rem,
	.create_queue  = create_queue,
	.destroy_queue = destroy_queue,
	.sched_queue   = sched_queue,
	.ord_enq_multi = ord_enq_multi,
	.ord_stash_release = ord_stash_release,
	.init_global   = init_global,
	.term_global   = term_global,
	.init_local    = init_local,
	.term_local    = term_local,
	.order_lock    = order_lock,
	.order_unlock  = order_unlock,
	.max_ordered_locks = max_ordered_locks,
	.get_config    = get_config,
	.sched_api     = sched_api,
};

/* Fill in scheduler API calls */
const _odp_schedule_api_fn_t _odp_schedule_sp_api = {
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
