/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/packet_io.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <odp/packet.h>
#include <odp_packet_internal.h>
#include <odp_internal.h>
#include <odp/spinlock.h>
#include <odp/shared_memory.h>
#include <odp_packet_socket.h>
#include <odp/config.h>
#include <odp_queue_internal.h>
#include <odp_schedule_internal.h>
#include <odp_debug_internal.h>

#include <string.h>

/* MTU to be reported for the "loop" interface */
#define PKTIO_LOOP_MTU 1500
/* MAC address for the "loop" interface */
static const char pktio_loop_mac[] = {0x02, 0xe9, 0x34, 0x80, 0x73, 0x01};

static pktio_table_t *pktio_tbl;

/* pktio pointer entries ( for inlines) */
void *pktio_entry_ptr[ODP_CONFIG_PKTIO_ENTRIES];


int odp_pktio_init_global(void)
{
	char name[ODP_QUEUE_NAME_LEN];
	pktio_entry_t *pktio_entry;
	queue_entry_t *queue_entry;
	odp_queue_t qid;
	int id;
	odp_shm_t shm;

	shm = odp_shm_reserve("odp_pktio_entries",
			      sizeof(pktio_table_t),
			      sizeof(pktio_entry_t), 0);
	pktio_tbl = odp_shm_addr(shm);

	if (pktio_tbl == NULL)
		return -1;

	memset(pktio_tbl, 0, sizeof(pktio_table_t));

	odp_spinlock_init(&pktio_tbl->lock);

	for (id = 1; id <= ODP_CONFIG_PKTIO_ENTRIES; ++id) {
		pktio_entry = &pktio_tbl->entries[id - 1];

		odp_spinlock_init(&pktio_entry->s.lock);
		odp_spinlock_init(&pktio_entry->s.cls.lock);

		pktio_entry_ptr[id - 1] = pktio_entry;
		/* Create a default output queue for each pktio resource */
		snprintf(name, sizeof(name), "%i-pktio_outq_default", (int)id);
		name[ODP_QUEUE_NAME_LEN-1] = '\0';

		qid = odp_queue_create(name, ODP_QUEUE_TYPE_PKTOUT, NULL);
		if (qid == ODP_QUEUE_INVALID)
			return -1;
		pktio_entry->s.outq_default = qid;

		queue_entry = queue_to_qentry(qid);
		queue_entry->s.pktout = _odp_cast_scalar(odp_pktio_t, id);
	}

	return 0;
}

int odp_pktio_term_global(void)
{
	pktio_entry_t *pktio_entry;
	int ret = 0;
	int id;

	for (id = 1; id <= ODP_CONFIG_PKTIO_ENTRIES; ++id) {
		pktio_entry = &pktio_tbl->entries[id - 1];
		odp_queue_destroy(pktio_entry->s.outq_default);
	}

	ret = odp_shm_free(odp_shm_lookup("odp_pktio_entries"));
	if (ret < 0)
		ODP_ERR("shm free failed for odp_pktio_entries");

	return ret;
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

static void init_pktio_entry(pktio_entry_t *entry)
{
	set_taken(entry);
	entry->s.inq_default = ODP_QUEUE_INVALID;
	memset(&entry->s.pkt_dpdk, 0, sizeof(entry->s.pkt_dpdk));
	/* Save pktio parameters, type is the most useful */
}

static odp_pktio_t alloc_lock_pktio_entry(void)
{
	odp_pktio_t id;
	pktio_entry_t *entry;
	int i;

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		entry = &pktio_tbl->entries[i];
		if (is_free(entry)) {
			/*lock_entry_classifier(entry);*/
			if (is_free(entry)) {
				init_pktio_entry(entry);
				id = _odp_cast_scalar(odp_pktio_t, i + 1);
				return id; /* return with entry locked! */
			}
			/*unlock_entry_classifier(entry);*/
		}
	}

	return ODP_PKTIO_INVALID;
}

static int free_pktio_entry(odp_pktio_t id)
{
	pktio_entry_t *entry = get_pktio_entry(id);

	if (entry == NULL)
		return -1;

	set_free(entry);

	return 0;
}

static int init_loop(pktio_entry_t *entry, odp_pktio_t id)
{
	char loopq_name[ODP_QUEUE_NAME_LEN];

	entry->s.type = ODP_PKTIO_TYPE_LOOPBACK;
	snprintf(loopq_name, sizeof(loopq_name), "%" PRIu64 "-pktio_loopq",
		 odp_pktio_to_u64(id));
	entry->s.loopq = odp_queue_create(loopq_name,
					  ODP_QUEUE_TYPE_POLL, NULL);

	if (entry->s.loopq == ODP_QUEUE_INVALID)
		return -1;

	return 0;
}

odp_pktio_t odp_pktio_open(const char *dev, odp_pool_t pool)
{
	odp_pktio_t id;
	pktio_entry_t *pktio_entry;
	int res;
	uint32_t pool_id;
	pool_entry_t *pool_entry;

	id = odp_pktio_lookup(dev);
	if (id != ODP_PKTIO_INVALID) {
		/* interface is already open */
		__odp_errno = EEXIST;
		return ODP_PKTIO_INVALID;
	}

	ODP_DBG("Allocating dpdk pktio\n");

	odp_spinlock_lock(&pktio_tbl->lock);

	id = alloc_lock_pktio_entry();
	if (id == ODP_PKTIO_INVALID) {
		ODP_ERR("No resources available.\n");
		return ODP_PKTIO_INVALID;
	}
	/* if successful, alloc_pktio_entry() returns with the entry locked */

	pktio_entry = get_pktio_entry(id);
	if (!pktio_entry) {
		odp_spinlock_unlock(&pktio_tbl->lock);
		return ODP_PKTIO_INVALID;
	}

	if (strcmp(dev, "loop") == 0) {
		res = init_loop(pktio_entry, id);
	} else {
		pktio_entry->s.type = ODP_PKTIO_TYPE_DPDK;
		res = setup_pkt_dpdk(&pktio_entry->s.pkt_dpdk, dev, pool);
	}

	if (res != 0) {
			close_pkt_dpdk(&pktio_entry->s.pkt_dpdk);
			/*unlock_entry_classifier(pktio_entry);*/
			free_pktio_entry(id);
			odp_spinlock_unlock(&pktio_tbl->lock);
			return ODP_PKTIO_INVALID;
	}

	snprintf(pktio_entry->s.name, IFNAMSIZ, "%s", dev);


	pool_id = pool_handle_to_index(pool);
	pool_entry = get_pool_entry(pool_id);
	pool_entry->s.pktio = id;

	unlock_entry(pktio_entry);
	/*unlock_entry_classifier(pktio_entry);*/
	odp_spinlock_unlock(&pktio_tbl->lock);

	return id;
}

int odp_pktio_close(odp_pktio_t id)
{
	pktio_entry_t *entry;
	int res = -1;
	uint32_t pool_id;
	pool_entry_t *pool_entry;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("No entry\n");
		return -1;
	}

	lock_entry(entry);
	if (!is_free(entry)) {
		switch (entry->s.type) {
		case ODP_PKTIO_TYPE_LOOPBACK:
			res = odp_queue_destroy(entry->s.loopq);
			break;
		case ODP_PKTIO_TYPE_DPDK:
			res  = close_pkt_dpdk(&entry->s.pkt_dpdk);
			break;
		default:
			break;
		}
		res |= free_pktio_entry(id);
	}

	pool_id = pool_handle_to_index(entry->s.pkt_dpdk.pool);
	pool_entry = get_pool_entry(pool_id);
	pool_entry->s.pktio = ODP_PKTIO_INVALID;

	unlock_entry(entry);

	if (res != 0)
		return -1;

	return 0;
}

odp_pktio_t odp_pktio_lookup(const char *dev)
{
	odp_pktio_t id = ODP_PKTIO_INVALID;
	pktio_entry_t *entry;
	int i;

	odp_spinlock_lock(&pktio_tbl->lock);

	for (i = 1; i <= ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		entry = get_pktio_entry(_odp_cast_scalar(odp_pktio_t, i));
		if (is_free(entry))
			continue;

		lock_entry(entry);

		if (!is_free(entry) &&
		    strncmp(entry->s.name, dev, IFNAMSIZ) == 0)
			id = _odp_cast_scalar(odp_pktio_t, i);

		unlock_entry(entry);

		if (id != ODP_PKTIO_INVALID)
			break;
	}

	odp_spinlock_unlock(&pktio_tbl->lock);

	return id;
}

int odp_pktio_recv(odp_pktio_t id, odp_packet_t pkt_table[], int len)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	int pkts;
	int i;

	if (pktio_entry == NULL)
		return -1;

	odp_pktio_send(id, pkt_table, 0);

	lock_entry(pktio_entry);
	pkts = recv_pkt_dpdk(&pktio_entry->s.pkt_dpdk, pkt_table, len);
	unlock_entry(pktio_entry);
	if (pkts < 0)
		return pkts;

	for (i = 0; i < pkts; ++i) {
		odp_packet_hdr(pkt_table[i])->input = id;
		memset(&odp_packet_hdr(pkt_table[i])->l2_offset,
		       ODP_PACKET_OFFSET_INVALID,
		       3 * sizeof(odp_packet_hdr(pkt_table[i])->l2_offset));
	}

	return pkts;
}

int odp_pktio_send(odp_pktio_t id, odp_packet_t pkt_table[], int len)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	pkt_dpdk_t *pkt_dpdk;
	int pkts;

	if (pktio_entry == NULL)
		return -1;
	pkt_dpdk = &pktio_entry->s.pkt_dpdk;

	lock_entry(pktio_entry);
	pkts = rte_eth_tx_burst(pkt_dpdk->portid, pkt_dpdk->queueid,
				(struct rte_mbuf **)pkt_table, len);
	unlock_entry(pktio_entry);

	return pkts;
}

int odp_pktio_inq_setdef(odp_pktio_t id, odp_queue_t queue)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	queue_entry_t *qentry;

	if (pktio_entry == NULL || queue == ODP_QUEUE_INVALID)
		return -1;

	qentry = queue_to_qentry(queue);

	if (qentry->s.type != ODP_QUEUE_TYPE_PKTIN)
		return -1;

	lock_entry(pktio_entry);
	pktio_entry->s.inq_default = queue;
	unlock_entry(pktio_entry);

	switch (qentry->s.type) {
	/* Change to ODP_QUEUE_TYPE_POLL when ODP_QUEUE_TYPE_PKTIN is removed */
	case ODP_QUEUE_TYPE_PKTIN:
		/* User polls the input queue */
		queue_lock(qentry);
		qentry->s.pktin = id;
		queue_unlock(qentry);

	/* Uncomment when ODP_QUEUE_TYPE_PKTIN is removed
		break;
	case ODP_QUEUE_TYPE_SCHED:
	*/
		/* Packet input through the scheduler */
		if (schedule_pktio_start(id, ODP_SCHED_PRIO_LOWEST)) {
			ODP_ERR("Schedule pktio start failed\n");
			return -1;
		}
		break;
	default:
		ODP_ABORT("Bad queue type\n");
	}

	return 0;
}

int odp_pktio_inq_remdef(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	odp_queue_t queue;
	queue_entry_t *qentry;

	if (pktio_entry == NULL)
		return -1;

	lock_entry(pktio_entry);
	queue = pktio_entry->s.inq_default;
	qentry = queue_to_qentry(queue);

	queue_lock(qentry);
	qentry->s.pktin = ODP_PKTIO_INVALID;
	queue_unlock(qentry);

	pktio_entry->s.inq_default = ODP_QUEUE_INVALID;
	unlock_entry(pktio_entry);

	return 0;
}

odp_queue_t odp_pktio_inq_getdef(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	if (pktio_entry == NULL)
		return ODP_QUEUE_INVALID;

	return pktio_entry->s.inq_default;
}

odp_queue_t odp_pktio_outq_getdef(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	if (pktio_entry == NULL)
		return ODP_QUEUE_INVALID;

	return pktio_entry->s.outq_default;
}

int pktout_enqueue(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr)
{
	odp_packet_t pkt = _odp_packet_from_buffer((odp_buffer_t) buf_hdr);
	int len = 1;
	int nbr;

	nbr = odp_pktio_send(qentry->s.pktout, &pkt, len);
	return (nbr == len ? 0 : -1);
}

odp_buffer_hdr_t *pktout_dequeue(queue_entry_t *qentry)
{
	(void)qentry;
	return NULL;
}

int pktout_enq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[],
		     int num)
{
	odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
	int nbr;
	int i;

	for (i = 0; i < num; ++i)
		pkt_tbl[i] = _odp_packet_from_buffer((odp_buffer_t) buf_hdr[i]);

	nbr = odp_pktio_send(qentry->s.pktout, pkt_tbl, num);
	return (nbr == num ? 0 : -1);
}

int pktout_deq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[],
		     int num)
{
	(void)qentry;
	(void)buf_hdr;
	(void)num;

	return 0;
}

int pktin_enqueue(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr)
{
	/* Use default action */
	return queue_enq(qentry, buf_hdr);
}

odp_buffer_hdr_t *pktin_dequeue(queue_entry_t *qentry)
{
	odp_buffer_hdr_t *buf_hdr;

	buf_hdr = queue_deq(qentry);

	if (buf_hdr == NULL) {
		odp_packet_t pkt;
		odp_buffer_t buf;
		odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
		odp_buffer_hdr_t *tmp_hdr_tbl[QUEUE_MULTI_MAX];
		int pkts, i, j;

		pkts = odp_pktio_recv(qentry->s.pktin, pkt_tbl,
				      QUEUE_MULTI_MAX);

		if (pkts > 0) {
			pkt = pkt_tbl[0];
			buf = _odp_packet_to_buffer(pkt);
			buf_hdr = odp_buf_to_hdr(buf);

			for (i = 1, j = 0; i < pkts; ++i) {
				buf = _odp_packet_to_buffer(pkt_tbl[i]);
				tmp_hdr_tbl[j++] = odp_buf_to_hdr(buf);
			}
			queue_enq_multi(qentry, tmp_hdr_tbl, j);
		}
	}

	return buf_hdr;
}

int pktin_enq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[], int num)
{
	/* Use default action */
	return queue_enq_multi(qentry, buf_hdr, num);
}

int pktin_deq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[], int num)
{
	int nbr;

	nbr = queue_deq_multi(qentry, buf_hdr, num);

	if (nbr < num) {
		odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
		odp_buffer_hdr_t *tmp_hdr_tbl[QUEUE_MULTI_MAX];
		odp_buffer_t buf;
		int pkts, i;

		pkts = odp_pktio_recv(qentry->s.pktin, pkt_tbl,
				      QUEUE_MULTI_MAX);
		if (pkts > 0) {
			for (i = 0; i < pkts; ++i) {
				buf = _odp_packet_to_buffer(pkt_tbl[i]);
				tmp_hdr_tbl[i] = odp_buf_to_hdr(buf);
			}
			queue_enq_multi(qentry, tmp_hdr_tbl, pkts);
		}
	}

	return nbr;
}

int pktin_poll(pktio_entry_t *entry)
{
	odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	int num, num_enq, i;

	if (odp_unlikely(is_free(entry)))
		return -1;

	if (odp_unlikely(entry->s.inq_default == ODP_QUEUE_INVALID))
		return -1;

	num = odp_pktio_recv(entry->s.handle, pkt_tbl, QUEUE_MULTI_MAX);

	if (num < 0) {
		ODP_ERR("Packet recv error\n");
		return -1;
	}

	for (i = 0, num_enq = 0; i < num; ++i) {
		odp_buffer_t buf;
		odp_buffer_hdr_t *hdr;

		buf = _odp_packet_to_buffer(pkt_tbl[i]);
		hdr = odp_buf_to_hdr(buf);

		if (entry->s.cls_enabled) {
#if 0 /* Classifier not enabled yet */
			if (packet_classifier(entry->s.handle, pkt_tbl[i]) < 0)
				hdr_tbl[num_enq++] = hdr;
#endif
		} else {
			hdr_tbl[num_enq++] = hdr;
		}
	}

	if (num_enq) {
		queue_entry_t *qentry;
		qentry = queue_to_qentry(entry->s.inq_default);
		queue_enq_multi(qentry, hdr_tbl, num_enq);
	}

	return 0;
}

int odp_pktio_promisc_mode_set(odp_pktio_t id, odp_bool_t enable)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	entry->s.promisc = enable;

	if (entry->s.type == ODP_PKTIO_TYPE_LOOPBACK) {
		unlock_entry(entry);
		return 0;
	}

	if (enable)
		rte_eth_promiscuous_enable(entry->s.pkt_dpdk.portid);
	else
		rte_eth_promiscuous_disable(entry->s.pkt_dpdk.portid);

	unlock_entry(entry);
	return 0;
}

int odp_pktio_promisc_mode(odp_pktio_t id)
{
	pktio_entry_t *entry;
	int promisc;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	promisc = rte_eth_promiscuous_get(entry->s.pkt_dpdk.portid);

	unlock_entry(entry);

	return promisc;
}

int odp_pktio_mac_addr(odp_pktio_t id, void *mac_addr, int addr_size)
{
	pktio_entry_t *entry;

	if (addr_size < ETH_ALEN) {
		/* Output buffer too small */
		return -1;
	}

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	switch (entry->s.type) {
	case ODP_PKTIO_TYPE_DPDK:
		rte_eth_macaddr_get(entry->s.pkt_dpdk.portid,
				    (struct ether_addr *)mac_addr);
		break;
	case ODP_PKTIO_TYPE_LOOPBACK:
		memcpy(mac_addr, pktio_loop_mac, ETH_ALEN);
		break;
	default:
		ODP_ABORT("Wrong socket type %d\n", entry->s.type);
	}

	unlock_entry(entry);

	return ETH_ALEN;
}

int odp_pktio_mtu(odp_pktio_t id)
{
	pktio_entry_t *entry;
	uint16_t mtu;
	int ret;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	if (entry->s.type == ODP_PKTIO_TYPE_LOOPBACK) {
		unlock_entry(entry);
		return PKTIO_LOOP_MTU;
	}

	ret = rte_eth_dev_get_mtu(entry->s.pkt_dpdk.portid,
			&mtu);
	unlock_entry(entry);
	if (ret < 0)
		return -2;

	return mtu;
}
