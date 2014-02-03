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

	pktio_tbl = odp_shm_reserve("odp_pktio_entries",
				    sizeof(pktio_table_t),
				    sizeof(pktio_entry_t));
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

odp_pktio_t odp_pktio_open(char *dev, odp_buffer_pool_t pool)
{
	odp_pktio_t id;
	pktio_entry_t *pktio_entry;
	int res;

	id = alloc_lock_pktio_entry();
	if (id == ODP_PKTIO_INVALID) {
		ODP_ERR("No resources available.\n");
		return ODP_PKTIO_INVALID;
	}
	/* iff successful, alloc_pktio_entry() returns with the entry locked */

	pktio_entry = get_entry(id);

	res = setup_pkt_sock(&pktio_entry->s.pkt_sock, dev, pool);
	if (res == -1) {
		close_pkt_sock(&pktio_entry->s.pkt_sock);
		free_pktio_entry(id);
		id = ODP_PKTIO_INVALID;
	}

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
		res  = close_pkt_sock(&entry->s.pkt_sock);
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
	pkts = recv_pkt_sock(&pktio_entry->s.pkt_sock, pkt_table, len);
	unlock_entry(pktio_entry);
	for (i = 0; i < pkts; ++i)
		odp_pktio_set_input(pkt_table[i], id);

	return pkts;
}

int odp_pktio_send(odp_pktio_t id, odp_packet_t pkt_table[], unsigned len)
{
	pktio_entry_t *pktio_entry = get_entry(id);
	int sent_pkts;

	if (pktio_entry == NULL)
		return -1;

	lock_entry(pktio_entry);
	sent_pkts = send_pkt_sock(&pktio_entry->s.pkt_sock, pkt_table, len);
	unlock_entry(pktio_entry);

	return sent_pkts;
}

int odp_pktio_inq_setdef(odp_pktio_t id, odp_queue_t queue)
{
	pktio_entry_t *pktio_entry = get_entry(id);
	queue_entry_t *qentry = queue_to_qentry(queue);

	if (pktio_entry == NULL || qentry == NULL)
		return -1;

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

int pktout_enqueue(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr)
{
	odp_packet_t pkt = odp_packet_from_buffer(buf_hdr->handle.handle);
	int len = 1;
	int nbr;

	nbr = odp_pktio_send(queue->s.pktout, &pkt, len);
	return (nbr == len ? 0 : -1);
}

odp_buffer_hdr_t *pktout_dequeue(queue_entry_t *queue)
{
	(void)queue;
	return NULL;
}

int pktin_enqueue(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr)
{
	/* Use default action */
	return queue_enq(queue, buf_hdr);
}

odp_buffer_hdr_t *pktin_dequeue(queue_entry_t *qentry)
{
	odp_buffer_hdr_t *buf_hdr;

	buf_hdr = queue_deq(qentry);

	if (buf_hdr == NULL) {
		odp_packet_t pkt;
		odp_buffer_t buf;
		odp_buffer_hdr_t *tmp_hdr;
		odp_packet_t pkt_tbl[ODP_PKTIN_QUEUE_MAX_BURST];
		int pkts, i;

		pkts = odp_pktio_recv(qentry->s.pktin, pkt_tbl,
				      ODP_PKTIN_QUEUE_MAX_BURST);

		if (pkts > 0) {
			pkt = pkt_tbl[0];
			buf = odp_buffer_from_packet(pkt);
			buf_hdr = odp_buf_to_hdr(buf);

			for (i = 1; i < pkts; ++i) {
				buf = odp_buffer_from_packet(pkt_tbl[i]);
				tmp_hdr = odp_buf_to_hdr(buf);
				queue_enq(qentry, tmp_hdr);
			}
		}
	}

	return buf_hdr;
}
