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
#include <odp_buffer_inlines.h>

#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

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

odp_pktio_t odp_pktio_open(const char *dev, odp_pool_t pool,
			   const odp_pktio_param_t *param ODP_UNUSED)
{
	odp_pktio_t id;
	pktio_entry_t *pktio_entry;
	int res;

	if (pool == ODP_POOL_INVALID)
		return ODP_PKTIO_INVALID;

	id = odp_pktio_lookup(dev);
	if (id != ODP_PKTIO_INVALID) {
		/* interface is already open */
		__odp_errno = EEXIST;
		return ODP_PKTIO_INVALID;
	}

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

	pktio_entry->s.handle = id;
	odp_ticketlock_init(&pktio_entry->s.rxl);
	odp_ticketlock_init(&pktio_entry->s.txl);

	unlock_entry(pktio_entry);
	/*unlock_entry_classifier(pktio_entry);*/
	odp_spinlock_unlock(&pktio_tbl->lock);

	return id;
}

int odp_pktio_close(odp_pktio_t id)
{
	pktio_entry_t *entry;
	int res = -1;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("No entry\n");
		return -1;
	}

	lock_entry(entry);
	if (!is_free(entry)) {
		odp_ticketlock_lock(&entry->s.rxl);
		odp_ticketlock_lock(&entry->s.txl);

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
		odp_ticketlock_unlock(&entry->s.txl);
		odp_ticketlock_unlock(&entry->s.rxl);
	}

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
		if (!entry || is_free(entry))
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

static int deq_loopback(pktio_entry_t *pktio_entry, odp_packet_t pkts[],
			unsigned len)
{
	int nbr, i;
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	queue_entry_t *qentry;

	qentry = queue_to_qentry(pktio_entry->s.loopq);
	nbr = queue_deq_multi(qentry, hdr_tbl, len);

	for (i = 0; i < nbr; ++i) {
		pkts[i] = _odp_packet_from_buffer(odp_hdr_to_buf(hdr_tbl[i]));
		_odp_packet_parse((odp_packet_hdr_t *)pkts[i]);
	}

	return nbr;
}

static unsigned rte_mempool_available(const struct rte_mempool *mp)
{
#if RTE_MEMPOOL_CACHE_MAX_SIZE > 0
	return rte_ring_count(mp->ring) + mp->local_cache[rte_lcore_id()].len;
#else
	return rte_ring_count(mp->ring);
#endif
}

static void _odp_pktio_send_completion(pktio_entry_t *pktio_entry)
{
	int i;
	struct rte_mbuf* dummy;
	pool_entry_t *pool_entry =
		get_pool_entry(_odp_typeval(pktio_entry->s.pkt_dpdk.pool));
	struct rte_mempool *rte_mempool = pool_entry->s.rte_mempool;
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;

	rte_eth_tx_burst(pkt_dpdk->portid, pkt_dpdk->queueid, &dummy, 0);

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		pktio_entry_t *entry = &pktio_tbl->entries[i];

		if (rte_mempool_available(rte_mempool) != 0)
			return;

		if (entry == pktio_entry)
			continue;

		if (odp_ticketlock_trylock(&entry->s.txl)) {
			if (!is_free(entry) &&
			    entry->s.type == ODP_PKTIO_TYPE_DPDK) {
				pkt_dpdk = &entry->s.pkt_dpdk;
				rte_eth_tx_burst(pkt_dpdk->portid,
						 pkt_dpdk->queueid, &dummy, 0);
			}
			odp_ticketlock_unlock(&entry->s.txl);
		}
	}

	return;
}

int odp_pktio_recv(odp_pktio_t id, odp_packet_t pkt_table[], int len)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	int pkts, i;

	if (pktio_entry == NULL)
		return -1;

	odp_ticketlock_lock(&pktio_entry->s.rxl);
	if (odp_likely(pktio_entry->s.type == ODP_PKTIO_TYPE_DPDK)) {
		pkts = recv_pkt_dpdk(&pktio_entry->s.pkt_dpdk, pkt_table, len);
		if (pkts == 0) {
			pool_entry_t *pool_entry =
				get_pool_entry(_odp_typeval(pktio_entry->s.pkt_dpdk.pool));
			struct rte_mempool *rte_mempool =
				pool_entry->s.rte_mempool;
			if (rte_mempool_available(rte_mempool) == 0)
				_odp_pktio_send_completion(pktio_entry);
		}
	} else {
		pkts = deq_loopback(pktio_entry, pkt_table, len);
	}
	odp_ticketlock_unlock(&pktio_entry->s.rxl);
	for (i = 0; i < pkts; ++i) {
		odp_packet_hdr(pkt_table[i])->input = id;
		_odp_packet_reset_parse(pkt_table[i]);
	}
	return pkts;
}

static int enq_loopback(pktio_entry_t *pktio_entry, odp_packet_t pkt_tbl[],
			unsigned len)
{
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	queue_entry_t *qentry;
	unsigned i;

	for (i = 0; i < len; ++i)
		hdr_tbl[i] = odp_buf_to_hdr(_odp_packet_to_buffer(pkt_tbl[i]));

	qentry = queue_to_qentry(pktio_entry->s.loopq);
	return queue_enq_multi(qentry, hdr_tbl, len, 0);
}

int odp_pktio_send(odp_pktio_t id, odp_packet_t pkt_table[], int len)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	pkt_dpdk_t *pkt_dpdk;
	int pkts;

	if (pktio_entry == NULL)
		return -1;
	pkt_dpdk = &pktio_entry->s.pkt_dpdk;

	odp_ticketlock_lock(&pktio_entry->s.txl);
	if (odp_likely(pktio_entry->s.type == ODP_PKTIO_TYPE_DPDK))
		pkts = rte_eth_tx_burst(pkt_dpdk->portid, pkt_dpdk->queueid,
					(struct rte_mbuf **)pkt_table, len);
	else
		pkts = enq_loopback(pktio_entry, pkt_table, len);
	odp_ticketlock_unlock(&pktio_entry->s.txl);

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

odp_buffer_hdr_t *pktout_dequeue(queue_entry_t *qentry ODP_UNUSED)
{
	ODP_ABORT("attempted dequeue from a pktout queue");
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
	return nbr;
}

int pktout_deq_multi(queue_entry_t *qentry ODP_UNUSED,
		     odp_buffer_hdr_t *buf_hdr[] ODP_UNUSED,
		     int num ODP_UNUSED)
{
	ODP_ABORT("attempted dequeue from a pktout queue");
	return 0;
}

int pktin_enqueue(queue_entry_t *qentry ODP_UNUSED,
		  odp_buffer_hdr_t *buf_hdr ODP_UNUSED, int sustain ODP_UNUSED)
{
	ODP_ABORT("attempted enqueue to a pktin queue");
	return -1;
}

odp_buffer_hdr_t *pktin_dequeue(queue_entry_t *qentry)
{
	odp_buffer_hdr_t *buf_hdr;
	odp_buffer_t buf;
	odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
	odp_buffer_hdr_t *tmp_hdr_tbl[QUEUE_MULTI_MAX];
	int pkts, i, j;

	buf_hdr = queue_deq(qentry);
	if (buf_hdr != NULL)
		return buf_hdr;

	pkts = odp_pktio_recv(qentry->s.pktin, pkt_tbl, QUEUE_MULTI_MAX);
	if (pkts <= 0)
		return NULL;

	for (i = 0, j = 0; i < pkts; ++i) {
		buf = _odp_packet_to_buffer(pkt_tbl[i]);
		buf_hdr = odp_buf_to_hdr(buf);
#if 0 /* Classifier not enabled yet */
		if (0 > packet_classifier(qentry->s.pktin, pkt_tbl[i]))
#endif
			tmp_hdr_tbl[j++] = buf_hdr;
	}

	if (0 == j)
		return NULL;

	if (j > 1)
		queue_enq_multi(qentry, &tmp_hdr_tbl[1], j - 1, 0);
	buf_hdr = tmp_hdr_tbl[0];
	return buf_hdr;
}

int pktin_enq_multi(queue_entry_t *qentry ODP_UNUSED,
		    odp_buffer_hdr_t *buf_hdr[] ODP_UNUSED,
		    int num ODP_UNUSED, int sustain ODP_UNUSED)
{
	ODP_ABORT("attempted enqueue to a pktin queue");
	return 0;
}

int pktin_deq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[], int num)
{
	int nbr;
	odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
	odp_buffer_hdr_t *tmp_hdr_tbl[QUEUE_MULTI_MAX];
	odp_buffer_hdr_t *tmp_hdr;
	odp_buffer_t buf;
	int pkts, i, j;

	nbr = queue_deq_multi(qentry, buf_hdr, num);
	if (odp_unlikely(nbr > num))
		ODP_ABORT("queue_deq_multi req: %d, returned %d\n",
			num, nbr);

	/** queue already has number of requsted buffers,
	 *  do not do receive in that case.
	 */
	if (nbr == num)
		return nbr;

	pkts = odp_pktio_recv(qentry->s.pktin, pkt_tbl, QUEUE_MULTI_MAX);
	if (pkts <= 0)
		return nbr;

	for (i = 0, j = 0; i < pkts; ++i) {
		buf = _odp_packet_to_buffer(pkt_tbl[i]);
		tmp_hdr = odp_buf_to_hdr(buf);
#if 0 /* Classifier not enabled yet */
		if (0 > packet_classifier(qentry->s.pktin, pkt_tbl[i]))
#endif
			tmp_hdr_tbl[j++] = tmp_hdr;
	}

	if (j)
		queue_enq_multi(qentry, tmp_hdr_tbl, j, 0);
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
		queue_enq_multi(qentry, hdr_tbl, num_enq, 0);
	}

	return 0;
}

static int _dpdk_vdev_promisc_mode_set(uint8_t port_id, int enable)
{
	struct rte_eth_dev_info dev_info = {0};
	struct ifreq ifr;
	int ret;
	int sockfd;

	rte_eth_dev_info_get(port_id, &dev_info);
	if_indextoname(dev_info.if_index, ifr.ifr_name);
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		close(sockfd);
		ODP_DBG("ioctl SIOCGIFFLAGS error\n");
		return -1;
	}

	if (enable)
		ifr.ifr_flags |= IFF_PROMISC;
	else
		ifr.ifr_flags &= ~(IFF_PROMISC);

	ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	if (ret < 0) {
		close(sockfd);
		ODP_DBG("ioctl SIOCSIFFLAGS error\n");
		return -1;
	}

	ret = ioctl(sockfd, SIOCGIFMTU, &ifr);
	if (ret < 0) {
		close(sockfd);
		ODP_DBG("ioctl SIOCGIFMTU error\n");
		return -1;
	}

	ODP_DBG("vdev promisc set to %d\n", enable);
	close(sockfd);
	return 0;
}

int odp_pktio_promisc_mode_set(odp_pktio_t id, odp_bool_t enable)
{
	pktio_entry_t *entry;
	uint8_t portid;
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

	entry->s.promisc = enable;

	if (entry->s.type == ODP_PKTIO_TYPE_LOOPBACK) {
		unlock_entry(entry);
		return 0;
	}

	portid = entry->s.pkt_dpdk.portid;
	if (enable)
		rte_eth_promiscuous_enable(portid);
	else
		rte_eth_promiscuous_disable(portid);

	if (entry->s.pkt_dpdk.vdev_sysc_promisc) {
		ret = _dpdk_vdev_promisc_mode_set(portid, enable);
		if (ret < 0)
			ODP_DBG("vdev promisc mode fail\n");
	}

	unlock_entry(entry);
	return 0;
}

static int _dpdk_vdev_promisc_mode(uint8_t port_id)
{
	struct rte_eth_dev_info dev_info = {0};
	struct ifreq ifr;
	int ret;
	int sockfd;

	rte_eth_dev_info_get(port_id, &dev_info);
	if_indextoname(dev_info.if_index, ifr.ifr_name);
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	close(sockfd);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCGIFFLAGS error\n");
		return -1;
	}

	if (ifr.ifr_flags & IFF_PROMISC) {
		ODP_DBG("promisc is 1\n");
		return 1;
	} else
		return 0;
}

int odp_pktio_promisc_mode(odp_pktio_t id)
{
	pktio_entry_t *entry;
	int promisc;
	uint8_t portid;

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

	portid = entry->s.pkt_dpdk.portid;

	if (entry->s.pkt_dpdk.vdev_sysc_promisc)
		promisc = _dpdk_vdev_promisc_mode(portid);
	else
		promisc = rte_eth_promiscuous_get(portid);

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

static int _dpdk_vdev_mtu(uint8_t port_id)
{
	struct rte_eth_dev_info dev_info = {0};
	struct ifreq ifr;
	int ret;
	int sockfd;

	rte_eth_dev_info_get(port_id, &dev_info);
	if_indextoname(dev_info.if_index, ifr.ifr_name);
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	ret = ioctl(sockfd, SIOCGIFMTU, &ifr);
	close(sockfd);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCGIFMTU error\n");
		return -1;
	}

	return ifr.ifr_mtu;
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
	if (ret < 0) {
		unlock_entry(entry);
		return -2;
	}

	/* some dpdk PMD vdev does not support getting mtu size,
	 * try to use system call if dpdk cannot get mtu value.
	 */
	if (mtu == 0)
		mtu = _dpdk_vdev_mtu(entry->s.pkt_dpdk.portid);

	unlock_entry(entry);

	return mtu;
}

int odp_pktio_start(odp_pktio_t id)
{
	int ret;
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	if (!pktio_entry) {
		ODP_ERR("No pktio found!\n");
		return -1;
	}

	ret = rte_eth_dev_start(pktio_entry->s.pkt_dpdk.portid);
	if (ret < 0) {
		ODP_ERR("rte_eth_dev_start:err=%d, port=%u\n",
			ret, pktio_entry->s.pkt_dpdk.portid);
		return ret;
	}

	return 0;
}

int odp_pktio_stop(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	if (!pktio_entry) {
		ODP_ERR("No pktio found!\n");
		return -1;
	}
	rte_eth_dev_stop(pktio_entry->s.pkt_dpdk.portid);
	return 0;
}

void odp_pktio_param_init(odp_pktio_param_t *params)
{
	memset(params, 0, sizeof(odp_pktio_param_t));
}
