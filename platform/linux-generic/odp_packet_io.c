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
#include <odp_hints.h>
#include <odp_config.h>
#include <odp_queue_internal.h>
#include <odp_schedule_internal.h>
#include <odp_debug.h>

#include <string.h>
#include <sys/ioctl.h>

typedef struct {
	pktio_entry_t entries[ODP_CONFIG_PKTIO_ENTRIES];
} pktio_table_t;

static pktio_table_t *pktio_tbl;


static pktio_entry_t *get_entry(odp_pktio_t id)
{
	if (odp_unlikely(id == ODP_PKTIO_INVALID ||
			 id > ODP_CONFIG_PKTIO_ENTRIES))
		return NULL;

	return &pktio_tbl->entries[id - 1];
}

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

	for (id = 1; id <= ODP_CONFIG_PKTIO_ENTRIES; ++id) {
		pktio_entry = get_entry(id);

		odp_spinlock_init(&pktio_entry->s.lock);

		/* Create a default output queue for each pktio resource */
		snprintf(name, sizeof(name), "%i-pktio_outq_default", (int)id);
		name[ODP_QUEUE_NAME_LEN-1] = '\0';

		qid = odp_queue_create(name, ODP_QUEUE_TYPE_PKTOUT, NULL);
		if (qid == ODP_QUEUE_INVALID)
			return -1;
		pktio_entry->s.outq_default = qid;

		queue_entry = queue_to_qentry(qid);
		queue_entry->s.pktout = id;
	}

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

static void init_pktio_entry(pktio_entry_t *entry)
{
	set_taken(entry);
	entry->s.inq_default = ODP_QUEUE_INVALID;
	memset(&entry->s.pkt_sock, 0, sizeof(entry->s.pkt_sock));
	memset(&entry->s.pkt_sock_mmap, 0, sizeof(entry->s.pkt_sock_mmap));
}

static odp_pktio_t alloc_lock_pktio_entry(void)
{
	odp_pktio_t id;
	pktio_entry_t *entry;
	int i;

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		entry = &pktio_tbl->entries[i];
		if (is_free(entry)) {
			lock_entry(entry);
			if (is_free(entry)) {
				init_pktio_entry(entry);
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

odp_pktio_t odp_pktio_open(const char *dev, odp_buffer_pool_t pool)
{
	odp_pktio_t id;
	pktio_entry_t *pktio_entry;
	int res;
	int fanout = 1;

	id = alloc_lock_pktio_entry();
	if (id == ODP_PKTIO_INVALID) {
		ODP_ERR("No resources available.\n");
		return ODP_PKTIO_INVALID;
	}
	/* if successful, alloc_pktio_entry() returns with the entry locked */

	pktio_entry = get_entry(id);
	if (!pktio_entry)
		return ODP_PKTIO_INVALID;

	ODP_DBG("ODP_PKTIO_USE_FANOUT: %d\n", fanout);
	if (getenv("ODP_PKTIO_DISABLE_SOCKET_MMAP") == NULL) {
		pktio_entry->s.type = ODP_PKTIO_TYPE_SOCKET_MMAP;
		res = setup_pkt_sock_mmap(&pktio_entry->s.pkt_sock_mmap, dev,
				pool, fanout);
		if (res != -1) {
			ODP_DBG("IO type: ODP_PKTIO_TYPE_SOCKET_MMAP\n");
			goto done;
		}
		close_pkt_sock_mmap(&pktio_entry->s.pkt_sock_mmap);
	}

	if (getenv("ODP_PKTIO_DISABLE_SOCKET_MMSG") == NULL) {
		pktio_entry->s.type = ODP_PKTIO_TYPE_SOCKET_MMSG;
		res = setup_pkt_sock(&pktio_entry->s.pkt_sock, dev, pool);
		if (res != -1) {
			ODP_DBG("IO type: ODP_PKTIO_TYPE_SOCKET_MMSG\n");
			goto done;
		}
		close_pkt_sock(&pktio_entry->s.pkt_sock);
	}

	if (getenv("ODP_PKTIO_DISABLE_SOCKET_BASIC") == NULL) {
		pktio_entry->s.type = ODP_PKTIO_TYPE_SOCKET_BASIC;
		res = setup_pkt_sock(&pktio_entry->s.pkt_sock, dev, pool);
		if (res != -1) {
			ODP_DBG("IO type: ODP_PKTIO_TYPE_SOCKET_BASIC\n");
			goto done;
		}
		close_pkt_sock(&pktio_entry->s.pkt_sock);
	}

	unlock_entry(pktio_entry);
	free_pktio_entry(id);
	ODP_ERR("Unable to init any I/O type.\n");
	return ODP_PKTIO_INVALID;

done:
	strncpy(pktio_entry->s.name, dev, IFNAMSIZ);
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
		switch (entry->s.type) {
		case ODP_PKTIO_TYPE_SOCKET_BASIC:
		case ODP_PKTIO_TYPE_SOCKET_MMSG:
			res  = close_pkt_sock(&entry->s.pkt_sock);
			break;
		case ODP_PKTIO_TYPE_SOCKET_MMAP:
			res  = close_pkt_sock_mmap(&entry->s.pkt_sock_mmap);
			break;
		default:
			break;
		}
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
	int pkts;
	int i;

	if (pktio_entry == NULL)
		return -1;

	lock_entry(pktio_entry);
	switch (pktio_entry->s.type) {
	case ODP_PKTIO_TYPE_SOCKET_BASIC:
		pkts = recv_pkt_sock_basic(&pktio_entry->s.pkt_sock,
				pkt_table, len);
		break;
	case ODP_PKTIO_TYPE_SOCKET_MMSG:
		pkts = recv_pkt_sock_mmsg(&pktio_entry->s.pkt_sock,
				pkt_table, len);
		break;
	case ODP_PKTIO_TYPE_SOCKET_MMAP:
		pkts = recv_pkt_sock_mmap(&pktio_entry->s.pkt_sock_mmap,
				pkt_table, len);
		break;
	default:
		pkts = -1;
		break;
	}

	unlock_entry(pktio_entry);
	if (pkts < 0)
		return pkts;

	for (i = 0; i < pkts; ++i)
		odp_pktio_set_input(pkt_table[i], id);

	return pkts;
}

int odp_pktio_send(odp_pktio_t id, odp_packet_t pkt_table[], unsigned len)
{
	pktio_entry_t *pktio_entry = get_entry(id);
	int pkts;

	if (pktio_entry == NULL)
		return -1;

	lock_entry(pktio_entry);
	switch (pktio_entry->s.type) {
	case ODP_PKTIO_TYPE_SOCKET_BASIC:
		pkts = send_pkt_sock_basic(&pktio_entry->s.pkt_sock,
				pkt_table, len);
		break;
	case ODP_PKTIO_TYPE_SOCKET_MMSG:
		pkts = send_pkt_sock_mmsg(&pktio_entry->s.pkt_sock,
				pkt_table, len);
		break;
	case ODP_PKTIO_TYPE_SOCKET_MMAP:
		pkts = send_pkt_sock_mmap(&pktio_entry->s.pkt_sock_mmap,
				pkt_table, len);
		break;
	default:
		pkts = -1;
	}
	unlock_entry(pktio_entry);

	return pkts;
}

int odp_pktio_inq_setdef(odp_pktio_t id, odp_queue_t queue)
{
	pktio_entry_t *pktio_entry = get_entry(id);
	queue_entry_t *qentry;

	if (pktio_entry == NULL || queue == ODP_QUEUE_INVALID)
		return -1;

	qentry = queue_to_qentry(queue);

	if (qentry->s.type != ODP_QUEUE_TYPE_PKTIN)
		return -1;

	lock_entry(pktio_entry);
	pktio_entry->s.inq_default = queue;
	unlock_entry(pktio_entry);

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

int pktout_enqueue(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr)
{
	odp_packet_t pkt = odp_packet_from_buffer(buf_hdr->handle.handle);
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
		pkt_tbl[i] = odp_packet_from_buffer(buf_hdr[i]->handle.handle);

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
	odp_buffer_t buf;
	odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
	odp_buffer_hdr_t *tmp_hdr_tbl[QUEUE_MULTI_MAX];
	int pkts, i;

	buf_hdr = queue_deq(qentry);
	if (buf_hdr != NULL)
		return buf_hdr;

	pkts = odp_pktio_recv(qentry->s.pktin, pkt_tbl, QUEUE_MULTI_MAX);
	if (pkts <= 0)
		return NULL;

	for (i = 0; i < pkts; ++i) {
		buf = odp_packet_to_buffer(pkt_tbl[i]);
		tmp_hdr_tbl[i] = odp_buf_to_hdr(buf);
	}

	queue_enq_multi(qentry, tmp_hdr_tbl, pkts);
	buf_hdr = tmp_hdr_tbl[0];
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
	odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
	odp_buffer_hdr_t *tmp_hdr_tbl[QUEUE_MULTI_MAX];
	odp_buffer_t buf;
	int pkts, i;

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

	for (i = 0; i < pkts; ++i) {
		buf = odp_packet_to_buffer(pkt_tbl[i]);
		tmp_hdr_tbl[i] = odp_buf_to_hdr(buf);
	}

	queue_enq_multi(qentry, tmp_hdr_tbl, pkts);
	return nbr;
}

int odp_pktio_set_mtu(odp_pktio_t id, int mtu)
{
	pktio_entry_t *entry;
	int sockfd;
	struct ifreq ifr;
	int ret;

	if (mtu <= 0) {
		ODP_DBG("illegal MTU value %d\n", mtu);
		return -1;
	}

	entry = get_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	if (entry->s.pkt_sock_mmap.sockfd)
		sockfd = entry->s.pkt_sock_mmap.sockfd;
	else
		sockfd = entry->s.pkt_sock.sockfd;

	strncpy(ifr.ifr_name, entry->s.name, IFNAMSIZ);
	ifr.ifr_mtu = mtu;

	ret = ioctl(sockfd, SIOCSIFMTU, (caddr_t)&ifr);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCSIFMTU error\n");
		return -1;
	}

	return 0;
}

int odp_pktio_mtu(odp_pktio_t id)
{
	pktio_entry_t *entry;
	int sockfd;
	struct ifreq ifr;
	int ret;

	entry = get_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	if (entry->s.pkt_sock_mmap.sockfd)
		sockfd = entry->s.pkt_sock_mmap.sockfd;
	else
		sockfd = entry->s.pkt_sock.sockfd;

	strncpy(ifr.ifr_name, entry->s.name, IFNAMSIZ);

	ret = ioctl(sockfd, SIOCGIFMTU, &ifr);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCGIFMTU error\n");
		return -1;
	}

	return ifr.ifr_mtu;
}
