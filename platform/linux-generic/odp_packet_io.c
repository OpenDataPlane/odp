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
#include <odp_classification_internal.h>
#include <odp_debug_internal.h>

#include <string.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <errno.h>

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
	int pktio_if;

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
		odp_spinlock_init(&pktio_entry->s.cls.l2_cos_table.lock);
		odp_spinlock_init(&pktio_entry->s.cls.l3_cos_table.lock);

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

	for (pktio_if = 0; pktio_if_ops[pktio_if]; ++pktio_if) {
		if (pktio_if_ops[pktio_if]->init)
			if (pktio_if_ops[pktio_if]->init())
				ODP_ERR("failed to initialized pktio type %d",
					pktio_if);
	}

	return 0;
}

int odp_pktio_term_global(void)
{
	pktio_entry_t *pktio_entry;
	int ret = 0;
	int id;
	int pktio_if;

	for (pktio_if = 0; pktio_if_ops[pktio_if]; ++pktio_if) {
		if (pktio_if_ops[pktio_if]->term)
			if (pktio_if_ops[pktio_if]->term())
				ODP_ERR("failed to terminate pktio type %d",
					pktio_if);
	}

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

static void lock_entry_classifier(pktio_entry_t *entry)
{
	odp_spinlock_lock(&entry->s.lock);
	odp_spinlock_lock(&entry->s.cls.lock);
}

static void unlock_entry_classifier(pktio_entry_t *entry)
{
	odp_spinlock_unlock(&entry->s.cls.lock);
	odp_spinlock_unlock(&entry->s.lock);
}

static void init_pktio_entry(pktio_entry_t *entry)
{
	set_taken(entry);
	/* Currently classifier is enabled by default. It should be enabled
	   only when used. */
	entry->s.cls_enabled = 1;
	entry->s.inq_default = ODP_QUEUE_INVALID;

	pktio_classifier_init(entry);
}

static odp_pktio_t alloc_lock_pktio_entry(void)
{
	odp_pktio_t id;
	pktio_entry_t *entry;
	int i;

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		entry = &pktio_tbl->entries[i];
		if (is_free(entry)) {
			lock_entry_classifier(entry);
			if (is_free(entry)) {
				init_pktio_entry(entry);
				id = _odp_cast_scalar(odp_pktio_t, i + 1);
				return id; /* return with entry locked! */
			}
			unlock_entry_classifier(entry);
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

static odp_pktio_t setup_pktio_entry(const char *dev, odp_pool_t pool,
				     const odp_pktio_param_t *param)
{
	odp_pktio_t id;
	pktio_entry_t *pktio_entry;
	int ret = -1;
	int pktio_if;

	if (strlen(dev) >= IF_NAMESIZE) {
		/* ioctl names limitation */
		ODP_ERR("pktio name %s is too big, limit is %d bytes\n",
			dev, IF_NAMESIZE);
		return ODP_PKTIO_INVALID;
	}

	id = alloc_lock_pktio_entry();
	if (id == ODP_PKTIO_INVALID) {
		ODP_ERR("No resources available.\n");
		return ODP_PKTIO_INVALID;
	}
	/* if successful, alloc_pktio_entry() returns with the entry locked */

	pktio_entry = get_pktio_entry(id);
	if (!pktio_entry)
		return ODP_PKTIO_INVALID;

	memcpy(&pktio_entry->s.param, param, sizeof(odp_pktio_param_t));

	for (pktio_if = 0; pktio_if_ops[pktio_if]; ++pktio_if) {
		ret = pktio_if_ops[pktio_if]->open(id, pktio_entry, dev, pool);

		if (!ret) {
			pktio_entry->s.ops = pktio_if_ops[pktio_if];
			break;
		}
	}

	if (ret != 0) {
		unlock_entry_classifier(pktio_entry);
		free_pktio_entry(id);
		id = ODP_PKTIO_INVALID;
		ODP_ERR("Unable to init any I/O type.\n");
	} else {
		snprintf(pktio_entry->s.name, IF_NAMESIZE, "%s", dev);
		pktio_entry->s.state = STATE_STOP;
		unlock_entry_classifier(pktio_entry);
	}

	pktio_entry->s.handle = id;

	return id;
}

static int pool_type_is_packet(odp_pool_t pool)
{
	odp_pool_info_t pool_info;

	if (pool == ODP_POOL_INVALID)
		return 0;

	if (odp_pool_info(pool, &pool_info) != 0)
		return 0;

	return pool_info.params.type == ODP_POOL_PACKET;
}

odp_pktio_t odp_pktio_open(const char *dev, odp_pool_t pool,
			   const odp_pktio_param_t *param)
{
	odp_pktio_t id;

	ODP_ASSERT(pool_type_is_packet(pool));

	id = odp_pktio_lookup(dev);
	if (id != ODP_PKTIO_INVALID) {
		/* interface is already open */
		__odp_errno = EEXIST;
		return ODP_PKTIO_INVALID;
	}

	odp_spinlock_lock(&pktio_tbl->lock);
	id = setup_pktio_entry(dev, pool, param);
	odp_spinlock_unlock(&pktio_tbl->lock);

	return id;
}

int odp_pktio_close(odp_pktio_t id)
{
	pktio_entry_t *entry;
	int res = -1;

	entry = get_pktio_entry(id);
	if (entry == NULL)
		return -1;

	lock_entry(entry);
	if (!is_free(entry)) {
		res = entry->s.ops->close(entry);
		res |= free_pktio_entry(id);
	}
	unlock_entry(entry);

	if (res != 0)
		return -1;

	return 0;
}

int odp_pktio_start(odp_pktio_t id)
{
	pktio_entry_t *entry;
	int res = 0;

	entry = get_pktio_entry(id);
	if (!entry)
		return -1;

	lock_entry(entry);
	if (entry->s.ops->start)
		res = entry->s.ops->start(entry);
	if (!res)
		entry->s.state = STATE_START;
	unlock_entry(entry);

	return res;
}

int odp_pktio_stop(odp_pktio_t id)
{
	pktio_entry_t *entry;
	int res = 0;

	entry = get_pktio_entry(id);
	if (!entry)
		return -1;

	lock_entry(entry);
	if (entry->s.ops->stop)
		res = entry->s.ops->stop(entry);
	if (!res)
		entry->s.state = STATE_STOP;
	unlock_entry(entry);

	return res;
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
		    strncmp(entry->s.name, dev, IF_NAMESIZE) == 0)
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

	lock_entry(pktio_entry);
	if (pktio_entry->s.state == STATE_STOP) {
		unlock_entry(pktio_entry);
		__odp_errno = EPERM;
		return -1;
	}
	pkts = pktio_entry->s.ops->recv(pktio_entry, pkt_table, len);
	unlock_entry(pktio_entry);

	if (pkts < 0)
		return pkts;

	for (i = 0; i < pkts; ++i)
		odp_packet_hdr(pkt_table[i])->input = id;

	return pkts;
}

int odp_pktio_send(odp_pktio_t id, odp_packet_t pkt_table[], int len)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	int pkts;

	if (pktio_entry == NULL)
		return -1;

	lock_entry(pktio_entry);
	if (pktio_entry->s.state == STATE_STOP) {
		unlock_entry(pktio_entry);
		__odp_errno = EPERM;
		return -1;
	}
	pkts = pktio_entry->s.ops->send(pktio_entry, pkt_table, len);
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
	odp_packet_t pkt = _odp_packet_from_buffer(buf_hdr->handle.handle);
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
		pkt_tbl[i] = _odp_packet_from_buffer(buf_hdr[i]->handle.handle);

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
		if (0 > packet_classifier(qentry->s.pktin, pkt_tbl[i]))
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
		if (0 > packet_classifier(qentry->s.pktin, pkt_tbl[i]))
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

	if (entry->s.state == STATE_STOP)
		return 0;

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
			if (packet_classifier(entry->s.handle, pkt_tbl[i]) < 0)
				hdr_tbl[num_enq++] = hdr;
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

int odp_pktio_mtu(odp_pktio_t id)
{
	pktio_entry_t *entry;
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
	ret = entry->s.ops->mtu_get(entry);

	unlock_entry(entry);
	return ret;
}

int odp_pktio_promisc_mode_set(odp_pktio_t id, odp_bool_t enable)
{
	pktio_entry_t *entry;
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

	ret = entry->s.ops->promisc_mode_set(entry, enable);

	unlock_entry(entry);
	return ret;
}

int odp_pktio_promisc_mode(odp_pktio_t id)
{
	pktio_entry_t *entry;
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

	ret = entry->s.ops->promisc_mode_get(entry);
	unlock_entry(entry);

	return ret;
}


int odp_pktio_mac_addr(odp_pktio_t id, void *mac_addr, int addr_size)
{
	pktio_entry_t *entry;
	int ret = ETH_ALEN;

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

	ret = entry->s.ops->mac_get(entry, mac_addr);
	unlock_entry(entry);

	return ret;
}
