/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string.h>
#include <odp/api/ticketlock.h>
#include <odp/api/thread.h>
#include <odp/api/time.h>
#include <odp/api/schedule.h>
#include <odp_schedule_if.h>
#include <odp_debug_internal.h>
#include <odp_align_internal.h>
#include <odp_config_internal.h>

#define NUM_QUEUE         ODP_CONFIG_QUEUES
#define NUM_PKTIO         ODP_CONFIG_PKTIO_ENTRIES
#define NUM_PRIO          3
#define NUM_STATIC_GROUP  3
#define NUM_GROUP         (NUM_STATIC_GROUP + 9)
#define NUM_PKTIN         32
#define LOWEST_QUEUE_PRIO (NUM_PRIO - 2)
#define PKTIN_PRIO        (NUM_PRIO - 1)
#define CMD_QUEUE         0
#define CMD_PKTIO         1
#define ROUNDUP_CACHE(x)  ODP_CACHE_LINE_SIZE_ROUNDUP(x)
#define GROUP_ALL         ODP_SCHED_GROUP_ALL
#define GROUP_WORKER      ODP_SCHED_GROUP_WORKER
#define GROUP_CONTROL     ODP_SCHED_GROUP_CONTROL

struct sched_cmd_t;

struct sched_cmd_s {
	struct sched_cmd_t *next;
	uint32_t           index;
	int                type;
	int                prio;
	int                group;
	int                init;
	int                num_pktin;
	int                pktin_idx[NUM_PKTIN];
};

typedef struct sched_cmd_t {
	struct sched_cmd_s s;
	uint8_t            pad[ROUNDUP_CACHE(sizeof(struct sched_cmd_s)) -
			       sizeof(struct sched_cmd_s)];
} sched_cmd_t ODP_ALIGNED_CACHE;

struct prio_queue_s {
	odp_ticketlock_t  lock;
	sched_cmd_t       *head;
	sched_cmd_t       *tail;
};

typedef	struct prio_queue_t {
	struct prio_queue_s s;
	uint8_t             pad[ROUNDUP_CACHE(sizeof(struct prio_queue_s)) -
				sizeof(struct prio_queue_s)];
} prio_queue_t ODP_ALIGNED_CACHE;

struct sched_group_s {
	odp_ticketlock_t  lock;

	struct {
		char          name[ODP_SCHED_GROUP_NAME_LEN + 1];
		odp_thrmask_t mask;
		int           allocated;
	} group[NUM_GROUP];
};

typedef struct sched_group_t {
	struct sched_group_s s;
	uint8_t              pad[ROUNDUP_CACHE(sizeof(struct sched_group_s)) -
				 sizeof(struct sched_group_s)];
} sched_group_t ODP_ALIGNED_CACHE;

typedef struct {
	sched_cmd_t   queue_cmd[NUM_QUEUE];
	sched_cmd_t   pktio_cmd[NUM_PKTIO];
	prio_queue_t  prio_queue[NUM_PRIO];
	sched_group_t sched_group;
} sched_global_t;

typedef struct {
	sched_cmd_t *cmd;
	int          pause;
	int          thr_id;
} sched_local_t;

static sched_global_t sched_global;
static __thread sched_local_t sched_local;

static int init_global(void)
{
	int i;
	sched_group_t *sched_group = &sched_global.sched_group;

	ODP_DBG("Using SP scheduler\n");

	memset(&sched_global, 0, sizeof(sched_global_t));

	for (i = 0; i < NUM_QUEUE; i++) {
		sched_global.queue_cmd[i].s.type  = CMD_QUEUE;
		sched_global.queue_cmd[i].s.index = i;
	}

	for (i = 0; i < NUM_PKTIO; i++) {
		sched_global.pktio_cmd[i].s.type  = CMD_PKTIO;
		sched_global.pktio_cmd[i].s.index = i;
		sched_global.pktio_cmd[i].s.prio  = PKTIN_PRIO;
	}

	for (i = 0; i < NUM_PRIO; i++)
		odp_ticketlock_init(&sched_global.prio_queue[i].s.lock);

	odp_ticketlock_init(&sched_group->s.lock);

	strncpy(sched_group->s.group[GROUP_ALL].name, "__group_all",
		ODP_SCHED_GROUP_NAME_LEN);
	odp_thrmask_zero(&sched_group->s.group[GROUP_ALL].mask);
	sched_group->s.group[GROUP_ALL].allocated = 1;

	strncpy(sched_group->s.group[GROUP_WORKER].name, "__group_worker",
		ODP_SCHED_GROUP_NAME_LEN);
	odp_thrmask_zero(&sched_group->s.group[GROUP_WORKER].mask);
	sched_group->s.group[GROUP_WORKER].allocated = 1;

	strncpy(sched_group->s.group[GROUP_CONTROL].name, "__group_control",
		ODP_SCHED_GROUP_NAME_LEN);
	odp_thrmask_zero(&sched_group->s.group[GROUP_CONTROL].mask);
	sched_group->s.group[GROUP_CONTROL].allocated = 1;

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
	int qi;

	for (qi = 0; qi < NUM_QUEUE; qi++) {
		if (sched_global.queue_cmd[qi].s.init) {
			/* todo: dequeue until empty ? */
			sched_cb_queue_destroy_finalize(qi);
		}
	}

	return 0;
}

static int term_local(void)
{
	return 0;
}

static int thr_add(odp_schedule_group_t group, int thr)
{
	sched_group_t *sched_group = &sched_global.sched_group;

	if (group < 0 || group >= NUM_GROUP)
		return -1;

	odp_ticketlock_lock(&sched_group->s.lock);

	if (!sched_group->s.group[group].allocated) {
		odp_ticketlock_unlock(&sched_group->s.lock);
		return -1;
	}

	odp_thrmask_set(&sched_group->s.group[group].mask, thr);

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static int thr_rem(odp_schedule_group_t group, int thr)
{
	sched_group_t *sched_group = &sched_global.sched_group;

	if (group < 0 || group >= NUM_GROUP)
		return -1;

	odp_ticketlock_lock(&sched_group->s.lock);

	if (!sched_group->s.group[group].allocated) {
		odp_ticketlock_unlock(&sched_group->s.lock);
		return -1;
	}

	odp_thrmask_clr(&sched_group->s.group[group].mask, thr);

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static int num_grps(void)
{
	return NUM_GROUP - NUM_STATIC_GROUP;
}

static int init_queue(uint32_t qi, const odp_schedule_param_t *sched_param)
{
	sched_group_t *sched_group = &sched_global.sched_group;
	odp_schedule_group_t group = sched_param->group;
	int prio = 0;

	if (group < 0 || group >= NUM_GROUP)
		return -1;

	if (!sched_group->s.group[group].allocated)
		return -1;

	if (sched_param->prio > 0)
		prio = LOWEST_QUEUE_PRIO;

	sched_global.queue_cmd[qi].s.prio  = prio;
	sched_global.queue_cmd[qi].s.group = group;
	sched_global.queue_cmd[qi].s.init  = 1;

	return 0;
}

static void destroy_queue(uint32_t qi)
{
	sched_global.queue_cmd[qi].s.prio  = 0;
	sched_global.queue_cmd[qi].s.group = 0;
	sched_global.queue_cmd[qi].s.init  = 0;
}

static inline void add_tail(sched_cmd_t *cmd)
{
	prio_queue_t *prio_queue;

	prio_queue   = &sched_global.prio_queue[cmd->s.prio];
	cmd->s.next  = NULL;

	odp_ticketlock_lock(&prio_queue->s.lock);

	if (prio_queue->s.head == NULL)
		prio_queue->s.head = cmd;
	else
		prio_queue->s.tail->s.next = cmd;

	prio_queue->s.tail = cmd;

	odp_ticketlock_unlock(&prio_queue->s.lock);
}

static inline sched_cmd_t *rem_head(int prio)
{
	prio_queue_t *prio_queue;
	sched_cmd_t *cmd;

	prio_queue = &sched_global.prio_queue[prio];

	odp_ticketlock_lock(&prio_queue->s.lock);

	if (prio_queue->s.head == NULL) {
		cmd = NULL;
	} else {
		sched_group_t *sched_group = &sched_global.sched_group;

		cmd = prio_queue->s.head;

		/* Remove head cmd only if thread belongs to the
		 * scheduler group. Otherwise continue to the next priority
		 * queue. */
		if (odp_thrmask_isset(&sched_group->s.group[cmd->s.group].mask,
				      sched_local.thr_id))
			prio_queue->s.head = cmd->s.next;
		else
			cmd = NULL;
	}

	odp_ticketlock_unlock(&prio_queue->s.lock);

	return cmd;
}

static int sched_queue(uint32_t qi)
{
	sched_cmd_t *cmd;

	cmd = &sched_global.queue_cmd[qi];
	add_tail(cmd);

	return 0;
}

static int ord_enq_multi(uint32_t queue_index, void *buf_hdr[], int num,
			 int sustain, int *ret)
{
	(void)queue_index;
	(void)buf_hdr;
	(void)num;
	(void)sustain;
	(void)ret;

	/* didn't consume the events */
	return 0;
}

static void pktio_start(int pktio_index, int num, int pktin_idx[])
{
	int i;
	sched_cmd_t *cmd;

	ODP_DBG("pktio index: %i, %i pktin queues %i\n",
		pktio_index, num, pktin_idx[0]);

	cmd = &sched_global.pktio_cmd[pktio_index];

	if (num > NUM_PKTIN)
		ODP_ABORT("Supports only %i pktin queues per interface\n",
			  NUM_PKTIN);

	for (i = 0; i < num; i++)
		cmd->s.pktin_idx[i] = pktin_idx[i];

	cmd->s.num_pktin = num;

	add_tail(cmd);
}

static inline sched_cmd_t *sched_cmd(int num_prio)
{
	int prio;

	for (prio = 0; prio < num_prio; prio++) {
		sched_cmd_t *cmd = rem_head(prio);

		if (cmd)
			return cmd;
	}

	return NULL;
}

static uint64_t schedule_wait_time(uint64_t ns)
{
	return ns;
}

static int schedule_multi(odp_queue_t *from, uint64_t wait,
			  odp_event_t events[], int max_events ODP_UNUSED)
{
	odp_time_t t1;
	int update_t1 = 1;

	if (sched_local.cmd) {
		/* Continue scheduling if queue is not empty */
		if (sched_cb_queue_empty(sched_local.cmd->s.index) == 0)
			add_tail(sched_local.cmd);

		sched_local.cmd = NULL;
	}

	if (odp_unlikely(sched_local.pause))
		return 0;

	while (1) {
		sched_cmd_t *cmd;
		uint32_t qi;
		int num;

		cmd = sched_cmd(NUM_PRIO);

		if (cmd && cmd->s.type == CMD_PKTIO) {
			if (sched_cb_pktin_poll(cmd->s.index, cmd->s.num_pktin,
						cmd->s.pktin_idx)) {
				/* Pktio stopped or closed. */
				sched_cb_pktio_stop_finalize(cmd->s.index);
			} else {
				/* Continue polling pktio. */
				add_tail(cmd);
			}

			/* run wait parameter checks under */
			cmd = NULL;
		}

		if (cmd == NULL) {
			/* All priority queues are empty */
			if (wait == ODP_SCHED_NO_WAIT)
				return 0;

			if (wait == ODP_SCHED_WAIT)
				continue;

			if (update_t1) {
				t1 = odp_time_sum(odp_time_local(),
						  odp_time_local_from_ns(wait));
				update_t1 = 0;
				continue;
			}

			if (odp_time_cmp(odp_time_local(), t1) < 0)
				continue;

			return 0;
		}

		qi  = cmd->s.index;
		num = sched_cb_queue_deq_multi(qi, events, 1);

		if (num > 0) {
			sched_local.cmd = cmd;

			if (from)
				*from = sched_cb_queue_handle(qi);

			return num;
		}

		if (num < 0) {
			/* Destroyed queue */
			sched_cb_queue_destroy_finalize(qi);
			continue;
		}

		if (num == 0) {
			/* Remove empty queue from scheduling. A dequeue
			 * operation to on an already empty queue moves
			 * it to NOTSCHED state and sched_queue() will
			 * be called on next enqueue. */
			continue;
		}
	}
}

static odp_event_t schedule(odp_queue_t *from, uint64_t wait)
{
	odp_event_t ev;

	if (schedule_multi(from, wait, &ev, 1) > 0)
		return ev;

	return ODP_EVENT_INVALID;
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
}

static void schedule_release_ordered(void)
{
}

static void schedule_prefetch(int num)
{
	(void)num;
}

static int schedule_num_prio(void)
{
	/* Lowest priority is used for pktin polling and is internal
	 * to the scheduler */
	return NUM_PRIO - 1;
}

static odp_schedule_group_t schedule_group_create(const char *name,
						  const odp_thrmask_t *thrmask)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	sched_group_t *sched_group = &sched_global.sched_group;
	int i;

	odp_ticketlock_lock(&sched_group->s.lock);

	for (i = NUM_STATIC_GROUP; i < NUM_GROUP; i++) {
		if (!sched_group->s.group[i].allocated) {
			char *grp_name = sched_group->s.group[i].name;

			if (name == NULL) {
				grp_name[0] = 0;
			} else {
				strncpy(grp_name, name,
					ODP_SCHED_GROUP_NAME_LEN - 1);
				grp_name[ODP_SCHED_GROUP_NAME_LEN - 1] = 0;
			}
			odp_thrmask_copy(&sched_group->s.group[i].mask,
					 thrmask);
			sched_group->s.group[i].allocated = 1;
			group = i;
			break;
		}
	}

	odp_ticketlock_unlock(&sched_group->s.lock);

	return group;
}

static int schedule_group_destroy(odp_schedule_group_t group)
{
	sched_group_t *sched_group = &sched_global.sched_group;

	if (group < NUM_STATIC_GROUP || group >= NUM_GROUP)
		return -1;

	odp_ticketlock_lock(&sched_group->s.lock);

	if (!sched_group->s.group[group].allocated) {
		odp_ticketlock_unlock(&sched_group->s.lock);
		return -1;
	}

	memset(&sched_group->s.group[group], 0,
	       sizeof(sched_group->s.group[0]));

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static odp_schedule_group_t schedule_group_lookup(const char *name)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	sched_group_t *sched_group = &sched_global.sched_group;
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
	sched_group_t *sched_group = &sched_global.sched_group;

	if (group < 0 || group >= NUM_GROUP)
		return -1;

	odp_ticketlock_lock(&sched_group->s.lock);

	if (!sched_group->s.group[group].allocated) {
		odp_ticketlock_unlock(&sched_group->s.lock);
		return -1;
	}

	odp_thrmask_or(&sched_group->s.group[group].mask,
		       &sched_group->s.group[group].mask,
		       thrmask);

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static int schedule_group_leave(odp_schedule_group_t group,
				const odp_thrmask_t *thrmask)
{
	sched_group_t *sched_group = &sched_global.sched_group;
	odp_thrmask_t *all = &sched_group->s.group[GROUP_ALL].mask;
	odp_thrmask_t not;

	if (group < 0 || group >= NUM_GROUP)
		return -1;

	odp_ticketlock_lock(&sched_group->s.lock);

	if (!sched_group->s.group[group].allocated) {
		odp_ticketlock_unlock(&sched_group->s.lock);
		return -1;
	}

	odp_thrmask_xor(&not, thrmask, all);
	odp_thrmask_and(&sched_group->s.group[group].mask,
			&sched_group->s.group[group].mask,
			&not);

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static int schedule_group_thrmask(odp_schedule_group_t group,
				  odp_thrmask_t *thrmask)
{
	sched_group_t *sched_group = &sched_global.sched_group;

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
	sched_group_t *sched_group = &sched_global.sched_group;

	if (group < 0 || group >= NUM_GROUP)
		return -1;

	odp_ticketlock_lock(&sched_group->s.lock);

	if (!sched_group->s.group[group].allocated) {
		odp_ticketlock_unlock(&sched_group->s.lock);
		return -1;
	}

	info->name    = sched_group->s.group[group].name;
	info->thrmask = sched_group->s.group[group].mask;

	odp_ticketlock_unlock(&sched_group->s.lock);

	return 0;
}

static void schedule_order_lock(unsigned lock_index)
{
	(void)lock_index;
}

static void schedule_order_unlock(unsigned lock_index)
{
	(void)lock_index;
}

/* Fill in scheduler interface */
const schedule_fn_t schedule_sp_fn = {
	.pktio_start   = pktio_start,
	.thr_add       = thr_add,
	.thr_rem       = thr_rem,
	.num_grps      = num_grps,
	.init_queue    = init_queue,
	.destroy_queue = destroy_queue,
	.sched_queue   = sched_queue,
	.ord_enq_multi = ord_enq_multi,
	.init_global   = init_global,
	.term_global   = term_global,
	.init_local    = init_local,
	.term_local    = term_local
};

/* Fill in scheduler API calls */
const schedule_api_t schedule_sp_api = {
	.schedule_wait_time       = schedule_wait_time,
	.schedule                 = schedule,
	.schedule_multi           = schedule_multi,
	.schedule_pause           = schedule_pause,
	.schedule_resume          = schedule_resume,
	.schedule_release_atomic  = schedule_release_atomic,
	.schedule_release_ordered = schedule_release_ordered,
	.schedule_prefetch        = schedule_prefetch,
	.schedule_num_prio        = schedule_num_prio,
	.schedule_group_create    = schedule_group_create,
	.schedule_group_destroy   = schedule_group_destroy,
	.schedule_group_lookup    = schedule_group_lookup,
	.schedule_group_join      = schedule_group_join,
	.schedule_group_leave     = schedule_group_leave,
	.schedule_group_thrmask   = schedule_group_thrmask,
	.schedule_group_info      = schedule_group_info,
	.schedule_order_lock      = schedule_order_lock,
	.schedule_order_unlock    = schedule_order_unlock
};
