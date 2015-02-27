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
#include <odp_config.h>
#include <odp_queue_internal.h>
#include <odp_schedule_internal.h>
#include <odp_classification_internal.h>
#include <odp_debug_internal.h>

#include <string.h>
#include <sys/ioctl.h>
#include <linux/if_arp.h>
#include <ifaddrs.h>

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
	entry->s.inq_default = ODP_QUEUE_INVALID;
	memset(&entry->s.pkt_sock, 0, sizeof(entry->s.pkt_sock));
	memset(&entry->s.pkt_sock_mmap, 0, sizeof(entry->s.pkt_sock_mmap));
	/* set sockfd to -1, because a valid socked might be initialized to 0 */
	entry->s.pkt_sock.sockfd = -1;
	entry->s.pkt_sock_mmap.sockfd = -1;

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
				id = i + 1;
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

odp_pktio_t odp_pktio_open(const char *dev, odp_buffer_pool_t pool)
{
	odp_pktio_t id;
	pktio_entry_t *pktio_entry;
	int res;
	int fanout = 1;
	char loop[IFNAMSIZ] = {0};
	char *loop_hint;

	if (strlen(dev) >= IFNAMSIZ) {
		/* ioctl names limitation */
		ODP_ERR("pktio name %s is too big, limit is %d bytes\n",
			dev, IFNAMSIZ);
		return ODP_PKTIO_INVALID;
	}

	if (!strcmp(dev, "loop")) {
		/* If hint with ODP_PKTIO_LOOPDEV is provided, use hint,
		 * if not try to find usable device.
		 */
		loop_hint = getenv("ODP_PKTIO_LOOPDEV");
		if (!loop_hint || (strlen(loop_hint) == 0)) {
			ODP_ERR("Set loop with ODP_PKTIO_LOOPDEV=ethX\n");
			return ODP_PKTIO_INVALID;
		}

		if (strlen(loop_hint) >= IFNAMSIZ) {
			ODP_ERR("pktio name %s is too big, limit is %d bytes\n",
				loop_hint, IFNAMSIZ);
			return ODP_PKTIO_INVALID;
		}

		memset(loop, 0, IFNAMSIZ);
		memcpy(loop, loop_hint, strlen(loop_hint));
		dev = loop;
		ODP_DBG("pktio using %s as loopback device\n", loop_hint);
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

	unlock_entry_classifier(pktio_entry);
	free_pktio_entry(id);
	ODP_ERR("Unable to init any I/O type.\n");
	return ODP_PKTIO_INVALID;

done:
	strncpy(pktio_entry->s.name, dev, IFNAMSIZ);
	unlock_entry_classifier(pktio_entry);
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

int odp_pktio_recv(odp_pktio_t id, odp_packet_t pkt_table[], unsigned len)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
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
		odp_packet_hdr(pkt_table[i])->input = id;

	return pkts;
}

int odp_pktio_send(odp_pktio_t id, odp_packet_t pkt_table[], unsigned len)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
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
	int pkts, i, j;

	buf_hdr = queue_deq(qentry);
	if (buf_hdr != NULL)
		return buf_hdr;

	pkts = odp_pktio_recv(qentry->s.pktin, pkt_tbl, QUEUE_MULTI_MAX);
	if (pkts <= 0)
		return NULL;

	for (i = 0, j = 0; i < pkts; ++i) {
		buf = odp_packet_to_buffer(pkt_tbl[i]);
		buf_hdr = odp_buf_to_hdr(buf);
		if (0 > packet_classifier(qentry->s.pktin, pkt_tbl[i]))
			tmp_hdr_tbl[j++] = buf_hdr;
	}

	if (0 == j)
		return NULL;

	if (j > 1)
		queue_enq_multi(qentry, &tmp_hdr_tbl[1], j-1);
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
		buf = odp_packet_to_buffer(pkt_tbl[i]);
		tmp_hdr = odp_buf_to_hdr(buf);
		if (0 > packet_classifier(qentry->s.pktin, pkt_tbl[i]))
			tmp_hdr_tbl[j++] = tmp_hdr;
	}

	if (j)
		queue_enq_multi(qentry, tmp_hdr_tbl, j);
	return nbr;
}

/** function should be called with locked entry */
static int sockfd_from_pktio_entry(pktio_entry_t *entry)
{
	switch (entry->s.type) {
	case ODP_PKTIO_TYPE_SOCKET_BASIC:
	case ODP_PKTIO_TYPE_SOCKET_MMSG:
		return entry->s.pkt_sock.sockfd;
	case ODP_PKTIO_TYPE_SOCKET_MMAP:
		return entry->s.pkt_sock_mmap.sockfd;
	default:
		ODP_ABORT("Wrong socket type %d\n", entry->s.type);
	}
}

int odp_pktio_mtu(odp_pktio_t id)
{
	pktio_entry_t *entry;
	int sockfd;
	struct ifreq ifr;
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

	sockfd = sockfd_from_pktio_entry(entry);
	strncpy(ifr.ifr_name, entry->s.name, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;

	ret = ioctl(sockfd, SIOCGIFMTU, &ifr);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCGIFMTU error\n");
		unlock_entry(entry);
		return -1;
	}

	unlock_entry(entry);
	return ifr.ifr_mtu;
}

int odp_pktio_promisc_mode_set(odp_pktio_t id, odp_bool_t enable)
{
	pktio_entry_t *entry;
	int sockfd;
	struct ifreq ifr;
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

	sockfd = sockfd_from_pktio_entry(entry);
	strncpy(ifr.ifr_name, entry->s.name, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;

	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		unlock_entry(entry);
		ODP_DBG("ioctl SIOCGIFFLAGS error\n");
		return -1;
	}

	if (enable)
		ifr.ifr_flags |= IFF_PROMISC;
	else
		ifr.ifr_flags &= ~(IFF_PROMISC);

	ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	if (ret < 0) {
		unlock_entry(entry);
		ODP_DBG("ioctl SIOCSIFFLAGS error\n");
		return -1;
	}

	unlock_entry(entry);
	return 0;
}

int odp_pktio_promisc_mode(odp_pktio_t id)
{
	pktio_entry_t *entry;
	int sockfd;
	struct ifreq ifr;
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

	sockfd = sockfd_from_pktio_entry(entry);
	strncpy(ifr.ifr_name, entry->s.name, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;

	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCGIFFLAGS error\n");
		unlock_entry(entry);
		return -1;
	}
	unlock_entry(entry);

	if (ifr.ifr_flags & IFF_PROMISC)
		return 1;
	else
		return 0;
}

size_t odp_pktio_mac_addr(odp_pktio_t id, void *mac_addr,
		       size_t addr_size)
{
	pktio_entry_t *entry;

	if (addr_size < ETH_ALEN)
		return 0;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return 0;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	switch (entry->s.type) {
	case ODP_PKTIO_TYPE_SOCKET_BASIC:
	case ODP_PKTIO_TYPE_SOCKET_MMSG:
		memcpy(mac_addr, entry->s.pkt_sock.if_mac,
		       ETH_ALEN);
		break;
	case ODP_PKTIO_TYPE_SOCKET_MMAP:
		memcpy(mac_addr, entry->s.pkt_sock_mmap.if_mac,
		       ETH_ALEN);
		break;
	default:
		ODP_ABORT("Wrong socket type %d\n", entry->s.type);
	}

	unlock_entry(entry);

	return ETH_ALEN;
}
