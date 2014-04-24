/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_packet_io.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <odp_packet.h>
#include <odp_packet_internal.h>
#include <odp_internal.h>
#include <odp_spinlock.h>
#include <odp_shared_memory.h>
#include <odp_packet_socket.h>
#ifdef ODP_HAVE_NETMAP
#include <odp_packet_netmap.h>
#endif
#include <odp_hints.h>
#include <odp_config.h>
#include <odp_queue_internal.h>
#include <odp_schedule_internal.h>
#include <odp_debug.h>
#include <odp_buffer_pool_internal.h>

#include <odp_pktio_socket.h>
#ifdef ODP_HAVE_NETMAP
#include <odp_pktio_netmap.h>
#endif

#include <string.h>

typedef struct {
	pktio_entry_t entries[ODP_CONFIG_PKTIO_ENTRIES];
} pktio_table_t;

static pktio_table_t *pktio_tbl;

struct pktio_device pktio_devs[] = {
	/* eth0 is used by Linux kernel */
	/* {.name = "eth0", .tx_hw_queue = 648, .rx_channel = 22, .rx_flow = 22, .port_id = 1}, */
	{.name = "eth1", .tx_hw_queue = 648, .rx_channel = 23, .rx_flow = 23, .port_id = 2},
	{.name = "eth2", .tx_hw_queue = 648, .rx_channel = 24, .rx_flow = 24, .port_id = 3},
	{.name = "eth3", .tx_hw_queue = 648, .rx_channel = 25, .rx_flow = 25, .port_id = 4},
};

static struct pktio_device *_odp_pktio_dev_lookup(const char *name)
{
	int i;
	int num = sizeof(pktio_devs)/sizeof(pktio_devs[0]);
	for (i = 0; i < num; i++)
		if (!strncmp(pktio_devs[i].name, name, PKTIO_DEV_MAX_NAME_LEN))
			return &pktio_devs[i];
	return NULL;
}

static pktio_entry_t *get_entry(odp_pktio_t id)
{
	if (odp_unlikely(id == ODP_PKTIO_INVALID ||
			 id > ODP_CONFIG_PKTIO_ENTRIES))
		return NULL;

	return &pktio_tbl->entries[id - 1];
}

int odp_pktio_init_global(void)
{
	pktio_entry_t *pktio_entry;
	int id, i;
	int dev_num = sizeof(pktio_devs)/sizeof(pktio_devs[0]);

	pktio_tbl = odp_shm_reserve("odp_pktio_entries",
				    sizeof(pktio_table_t),
				    sizeof(pktio_entry_t));
	if (pktio_tbl == NULL)
		return -1;

	memset(pktio_tbl, 0, sizeof(pktio_table_t));

	for (id = 1; id <= ODP_CONFIG_PKTIO_ENTRIES; ++id) {
		pktio_entry = get_entry(id);

		odp_spinlock_init(&pktio_entry->s.lock);
	}

	/* Close all used RX channels */
	for (i = 0; i < dev_num; i++)
		ti_em_osal_cppi_rx_channel_close(Cppi_CpDma_PASS_CPDMA,
						 pktio_devs[i].rx_channel);

	return 0;
}

int odp_pktio_init_local(void)
{
	return 0;
}

static int is_free(pktio_entry_t *entry)
{
	return (entry->s.taken == 0);
}

static void set_free(pktio_entry_t *entry)
{
	entry->s.taken = 0;
}

static void set_taken(pktio_entry_t *entry)
{
	entry->s.taken = 1;
}

static void lock_entry(pktio_entry_t *entry)
{
	odp_spinlock_lock(&entry->s.lock);
}

static void unlock_entry(pktio_entry_t *entry)
{
	odp_spinlock_unlock(&entry->s.lock);
}

static odp_pktio_t alloc_lock_pktio_entry(odp_pktio_params_t *params)
{
	odp_pktio_t id;
	pktio_entry_t *entry;
	int i;
	(void)params;
	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		entry = &pktio_tbl->entries[i];
		if (is_free(entry)) {
			lock_entry(entry);
			if (is_free(entry)) {
				set_taken(entry);
				entry->s.inq_default = ODP_QUEUE_INVALID;
				entry->s.outq_default = ODP_QUEUE_INVALID;
				id = i + 1;
				return id; /* return with entry locked! */
			}
			unlock_entry(entry);
		}
	}

	return ODP_PKTIO_INVALID;
}

static int free_pktio_entry(odp_pktio_t id)
{
	pktio_entry_t *entry = get_entry(id);

	if (entry == NULL)
		return -1;

	set_free(entry);

	return 0;
}

odp_pktio_t odp_pktio_open(const char *dev, odp_buffer_pool_t pool,
			   odp_pktio_params_t *params)
{
	odp_pktio_t id;
	pktio_entry_t *pktio_entry;
	char name[ODP_QUEUE_NAME_LEN];
	queue_entry_t *queue_entry;
	odp_queue_t qid = ODP_QUEUE_INVALID;

	if (params == NULL) {
		ODP_ERR("Invalid pktio params\n");
		return ODP_PKTIO_INVALID;
	}

	ODP_DBG("Allocating HW pktio\n");

	id = alloc_lock_pktio_entry(params);
	if (id == ODP_PKTIO_INVALID) {
		ODP_ERR("No resources available.\n");
		return ODP_PKTIO_INVALID;
	}
	/* if successful, alloc_pktio_entry() returns with the entry locked */

	pktio_entry = get_entry(id);

	/* Create a default output queue for each pktio resource */
	snprintf(name, sizeof(name), "%i-pktio_outq_default", (int)id);
	name[ODP_QUEUE_NAME_LEN-1] = '\0';

	pktio_entry->s.dev = _odp_pktio_dev_lookup(dev);
	if (!pktio_entry->s.dev) {
		free_pktio_entry(id);
		id = ODP_PKTIO_INVALID;
		goto unlock;
	}

	qid = _odp_queue_create(name, ODP_QUEUE_TYPE_PKTOUT, NULL,
				pktio_entry->s.dev->tx_hw_queue);
	ODP_DBG("Created queue %u for hw queue %d\n", (uint32_t)qid,
		pktio_entry->s.dev->tx_hw_queue);
	if (qid == ODP_QUEUE_INVALID) {
		free_pktio_entry(id);
		id = ODP_PKTIO_INVALID;
		goto unlock;
	}
	pktio_entry->s.in_pool = pool;
	pktio_entry->s.outq_default = qid;

	queue_entry = queue_to_qentry(qid);
	queue_entry->s.pktout = id;
	queue_entry->s.out_port_id = pktio_entry->s.dev->port_id;
unlock:
	unlock_entry(pktio_entry);
	return id;
}

int odp_pktio_close(odp_pktio_t id)
{
	pktio_entry_t *entry;
	int res = -1;

	entry = get_entry(id);
	if (entry == NULL)
		return -1;

	lock_entry(entry);
	if (!is_free(entry)) {
		/* FIXME: Here rx/tx channels should be closed */
		res |= free_pktio_entry(id);
	}

	unlock_entry(entry);

	if (res != 0)
		return -1;

	return 0;
}

void odp_pktio_set_input(odp_packet_t pkt, odp_pktio_t pktio)
{
	odp_packet_hdr(pkt)->input = pktio;
}

odp_pktio_t odp_pktio_get_input(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input;
}

int odp_pktio_recv(odp_pktio_t id, odp_packet_t pkt_table[], unsigned len)
{
	pktio_entry_t *pktio_entry = get_entry(id);
	unsigned pkts = 0;
	odp_buffer_t buf;

	if (pktio_entry == NULL)
		return -1;

	lock_entry(pktio_entry);

	if (pktio_entry->s.inq_default == ODP_QUEUE_INVALID) {
		char name[ODP_QUEUE_NAME_LEN];
		odp_queue_param_t qparam;
		odp_queue_t inq_def;
		/*
		 * Create a default input queue.
		 * FIXME: IT is a kind of WA for current ODP API usage.
		 * It should be revised.
		 */
		ODP_DBG("Creating default input queue\n");
		qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		qparam.sched.sync  = ODP_SCHED_SYNC_NONE;
		qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;
		snprintf(name, sizeof(name), "%i-pktio_inq_default", (int)id);
		name[ODP_QUEUE_NAME_LEN-1] = '\0';
		inq_def = odp_queue_create(name, ODP_QUEUE_TYPE_PKTIN, &qparam);
		if (inq_def == ODP_QUEUE_INVALID) {
			ODP_ERR("pktio queue creation failed\n");
			goto unlock;
		}

		if (odp_pktio_inq_setdef(id, inq_def)) {
			ODP_ERR("default input-Q setup\n");
			goto unlock;
		}
	}

	for (pkts = 0; pkts < len; pkts++) {
		buf = odp_queue_deq(pktio_entry->s.inq_default);
		if (!odp_buffer_is_valid(buf))
			break;

		pkt_table[pkts] = odp_packet_from_buffer(buf);
	}
unlock:
	unlock_entry(pktio_entry);
	return pkts;
}

int odp_pktio_send(odp_pktio_t id, odp_packet_t pkt_table[], unsigned len)
{
	pktio_entry_t *pktio_entry = get_entry(id);
	unsigned pkts;
	int ret;

	if (pktio_entry == NULL)
		return -1;

	lock_entry(pktio_entry);

	for (pkts = 0; pkts < len; pkts++) {
		ret = odp_queue_enq(pktio_entry->s.outq_default,
				    odp_buffer_from_packet(pkt_table[pkts]));
		if (ret)
			break;
	}
	unlock_entry(pktio_entry);
	return pkts;
}

int odp_pktio_inq_setdef(odp_pktio_t id, odp_queue_t queue)
{
	pktio_entry_t *pktio_entry = get_entry(id);
	queue_entry_t *qentry = queue_to_qentry(queue);

	if (pktio_entry == NULL || qentry == NULL)
		return -1;

	if (qentry->s.type != ODP_QUEUE_TYPE_PKTIN)
		return -1;

	pktio_entry->s.inq_default = queue;
	{
		uint32_t free_queue =
			_odp_pool_get_free_queue(pktio_entry->s.in_pool);
		ti_em_osal_cppi_rx_channel_close(Cppi_CpDma_PASS_CPDMA,
					pktio_entry->s.dev->rx_channel);
		ti_em_osal_cppi_rx_flow_open(Cppi_CpDma_PASS_CPDMA,
					     pktio_entry->s.dev->rx_flow,
					     qentry->s.hw_queue,
					     free_queue,
					     0);
		ti_em_osal_cppi_rx_channel_open(Cppi_CpDma_PASS_CPDMA,
						pktio_entry->s.dev->rx_channel);
		ODP_DBG("%s: Opened rx flow %u with dest queue: %u and free queue: %u\n",
			__func__,
			pktio_entry->s.dev->rx_flow,
			qentry->s.hw_queue,
			free_queue);
	}

	queue_lock(qentry);
	qentry->s.pktin = id;
	qentry->s.status = QUEUE_STATUS_SCHED;
	queue_unlock(qentry);

	odp_schedule_queue(queue, qentry->s.param.sched.prio);

	return 0;
}

int odp_pktio_inq_remdef(odp_pktio_t id)
{
	return odp_pktio_inq_setdef(id, ODP_QUEUE_INVALID);
}

odp_queue_t odp_pktio_inq_getdef(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_entry(id);

	if (pktio_entry == NULL)
		return ODP_QUEUE_INVALID;

	return pktio_entry->s.inq_default;
}

odp_queue_t odp_pktio_outq_getdef(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_entry(id);

	if (pktio_entry == NULL)
		return ODP_QUEUE_INVALID;

	return pktio_entry->s.outq_default;
}

int pktout_enqueue(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr)
{
	/*
	 * Set port number directly in a descriptor.
	 * TODO: Remove it when PA will be used.
	 */
	ti_em_cppi_set_psflags(&buf_hdr->desc, queue->s.out_port_id);
	return queue_enq(queue, buf_hdr);
}

int pktout_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num)
{
	int i;
	uint32_t port_id = queue->s.out_port_id;
	for (i = 0; i < num; i++)
		ti_em_cppi_set_psflags(&buf_hdr[i]->desc, port_id);
	return queue_enq_multi(queue, buf_hdr, num);
}

static inline void update_in_packet(odp_buffer_hdr_t *buf_hdr,
				    odp_pktio_t pktin)
{
	if (!buf_hdr)
		return;

	odp_buffer_t buf = hdr_to_odp_buf(buf_hdr);
	odp_packet_t pkt = odp_packet_from_buffer(buf);
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	size_t len = odp_packet_get_len(pkt);
	pkt_hdr->input = pktin;
	odp_packet_parse(pkt, len, 0);
}

odp_buffer_hdr_t *pktin_dequeue(queue_entry_t *queue)
{
	odp_buffer_hdr_t *buf_hdr;
	buf_hdr = queue_deq(queue);

	update_in_packet(buf_hdr, queue->s.pktin);
	return buf_hdr;
}

int pktin_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num)
{
	int i;
	num = queue_deq_multi(queue, buf_hdr, num);

	for (i = 0; i < num; i++)
		update_in_packet(buf_hdr[i], queue->s.pktin);
	return num;
}
