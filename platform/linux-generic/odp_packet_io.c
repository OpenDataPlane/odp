/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp/autoheader_internal.h>
#include <odp/api/packet_io.h>
#include <odp/api/plat/pktio_inlines.h>
#include <odp_packet_io_internal.h>
#include <odp/api/packet.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp_packet_internal.h>
#include <odp_init_internal.h>
#include <odp_errno_define.h>
#include <odp/api/spinlock.h>
#include <odp/api/ticketlock.h>
#include <odp/api/shared_memory.h>
#include <odp_config_internal.h>
#include <odp_queue_if.h>
#include <odp_schedule_if.h>
#include <odp_classification_internal.h>
#include <odp_debug_internal.h>
#include <odp_packet_io_ipc_internal.h>
#include <odp/api/time.h>
#include <odp/api/plat/time_inlines.h>
#include <odp_pcapng.h>
#include <odp/api/plat/queue_inlines.h>

#include <string.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <errno.h>
#include <time.h>

/* Sleep this many microseconds between pktin receive calls. Must be smaller
 * than 1000000 (a million), i.e. smaller than a second. */
#define SLEEP_USEC  1

/* Check total sleep time about every SLEEP_CHECK * SLEEP_USEC microseconds.
 * Must be power of two. */
#define SLEEP_CHECK 32

/* Max wait time supported to avoid potential overflow */
#define MAX_WAIT_TIME (UINT64_MAX / 1024)

static pktio_table_t *pktio_tbl;

/* pktio pointer entries ( for inlines) */
void *pktio_entry_ptr[ODP_CONFIG_PKTIO_ENTRIES];

static inline pktio_entry_t *pktio_entry_by_index(int index)
{
	return pktio_entry_ptr[index];
}

int _odp_pktio_init_global(void)
{
	pktio_entry_t *pktio_entry;
	int i;
	odp_shm_t shm;
	int pktio_if;

	shm = odp_shm_reserve("_odp_pktio_entries",
			      sizeof(pktio_table_t),
			      sizeof(pktio_entry_t),
			      0);
	if (shm == ODP_SHM_INVALID)
		return -1;

	pktio_tbl = odp_shm_addr(shm);
	memset(pktio_tbl, 0, sizeof(pktio_table_t));

	odp_spinlock_init(&pktio_tbl->lock);

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		pktio_entry = &pktio_tbl->entries[i];

		odp_ticketlock_init(&pktio_entry->s.rxl);
		odp_ticketlock_init(&pktio_entry->s.txl);
		odp_spinlock_init(&pktio_entry->s.cls.l2_cos_table.lock);
		odp_spinlock_init(&pktio_entry->s.cls.l3_cos_table.lock);

		pktio_entry_ptr[i] = pktio_entry;
	}

	for (pktio_if = 0; pktio_if_ops[pktio_if]; ++pktio_if) {
		if (pktio_if_ops[pktio_if]->init_global)
			if (pktio_if_ops[pktio_if]->init_global()) {
				ODP_ERR("failed to initialized pktio type %d",
					pktio_if);
				return -1;
			}
	}

	if (_ODP_PCAPNG) {
		if (_odp_pcapng_init_global()) {
			ODP_ERR("Failed to initialize pcapng\n");
			return -1;
		}
	}

	return 0;
}

int _odp_pktio_init_local(void)
{
	int pktio_if;

	for (pktio_if = 0; pktio_if_ops[pktio_if]; ++pktio_if) {
		if (pktio_if_ops[pktio_if]->init_local)
			if (pktio_if_ops[pktio_if]->init_local()) {
				ODP_ERR("failed to initialized pktio type %d",
					pktio_if);
				return -1;
			}
	}

	return 0;
}

static inline int is_free(pktio_entry_t *entry)
{
	return (entry->s.state == PKTIO_STATE_FREE);
}

static void lock_entry(pktio_entry_t *entry)
{
	odp_ticketlock_lock(&entry->s.rxl);
	odp_ticketlock_lock(&entry->s.txl);
}

static void unlock_entry(pktio_entry_t *entry)
{
	odp_ticketlock_unlock(&entry->s.txl);
	odp_ticketlock_unlock(&entry->s.rxl);
}

static void init_in_queues(pktio_entry_t *entry)
{
	int i;

	for (i = 0; i < PKTIO_MAX_QUEUES; i++) {
		entry->s.in_queue[i].queue = ODP_QUEUE_INVALID;
		entry->s.in_queue[i].pktin = PKTIN_INVALID;
	}
}

static void init_out_queues(pktio_entry_t *entry)
{
	int i;

	for (i = 0; i < PKTIO_MAX_QUEUES; i++) {
		entry->s.out_queue[i].queue  = ODP_QUEUE_INVALID;
		entry->s.out_queue[i].pktout = PKTOUT_INVALID;
	}
}

static void init_pktio_entry(pktio_entry_t *entry)
{
	pktio_cls_enabled_set(entry, 0);

	init_in_queues(entry);
	init_out_queues(entry);

	pktio_classifier_init(entry);
}

static odp_pktio_t alloc_lock_pktio_entry(void)
{
	pktio_entry_t *entry;
	int i;

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		entry = &pktio_tbl->entries[i];
		if (is_free(entry)) {
			lock_entry(entry);
			if (is_free(entry)) {
				odp_pktio_t hdl;

				entry->s.state = PKTIO_STATE_ACTIVE;
				init_pktio_entry(entry);
				hdl = _odp_cast_scalar(odp_pktio_t, i + 1);
				return hdl; /* return with entry locked! */
			}
			unlock_entry(entry);
		}
	}

	return ODP_PKTIO_INVALID;
}

/**
 * Strip optional pktio type from device name by moving start pointer
 *
 * @param      name      Packet IO device name
 * @param[out] type_out  Optional char array (len = PKTIO_NAME_LEN) for storing
 *                       pktio type. Ignored when NULL.
 *
 * @return Pointer to the beginning of device name
 */
static const char *strip_pktio_type(const char *name, char *type_out)
{
	const char *if_name;

	if (type_out)
		type_out[0] = '\0';

	/* Strip pktio type prefix <pktio_type>:<if_name> */
	if_name = strchr(name, ':');

	if (if_name) {
		int pktio_if;
		int type_len = if_name - name;
		char pktio_type[type_len + 1];

		strncpy(pktio_type, name, type_len);
		pktio_type[type_len] = '\0';

		/* Remove colon */
		if_name++;

		/* Match if_type to enabled pktio devices */
		for (pktio_if = 0; pktio_if_ops[pktio_if]; pktio_if++) {
			if (!strcmp(pktio_type, pktio_if_ops[pktio_if]->name)) {
				if (type_out)
					strcpy(type_out, pktio_type);
				/* Some pktio devices expect device names to
				 * begin with pktio type */
				if (!strcmp(pktio_type, "ipc") ||
				    !strcmp(pktio_type, "null") ||
				    !strcmp(pktio_type, "pcap") ||
				    !strcmp(pktio_type, "tap"))
					return name;

				return if_name;
			}
		}
	}
	return name;
}

static odp_pktio_t setup_pktio_entry(const char *name, odp_pool_t pool,
				     const odp_pktio_param_t *param)
{
	odp_pktio_t hdl;
	pktio_entry_t *pktio_entry;
	int ret = -1;
	int pktio_if;
	char pktio_type[PKTIO_NAME_LEN];
	const char *if_name;

	if (strlen(name) >= PKTIO_NAME_LEN - 1) {
		/* ioctl names limitation */
		ODP_ERR("pktio name %s is too big, limit is %d bytes\n",
			name, PKTIO_NAME_LEN - 1);
		return ODP_PKTIO_INVALID;
	}

	if_name = strip_pktio_type(name, pktio_type);

	hdl = alloc_lock_pktio_entry();
	if (hdl == ODP_PKTIO_INVALID) {
		ODP_ERR("No resources available.\n");
		return ODP_PKTIO_INVALID;
	}

	/* if successful, alloc_pktio_entry() returns with the entry locked */
	pktio_entry = get_pktio_entry(hdl);
	if (!pktio_entry) {
		unlock_entry(pktio_entry);
		return ODP_PKTIO_INVALID;
	}

	pktio_entry->s.pool = pool;
	memcpy(&pktio_entry->s.param, param, sizeof(odp_pktio_param_t));
	pktio_entry->s.handle = hdl;

	odp_pktio_config_init(&pktio_entry->s.config);

	for (pktio_if = 0; pktio_if_ops[pktio_if]; ++pktio_if) {
		/* Only use explicitly defined pktio type */
		if (strlen(pktio_type) &&
		    strcmp(pktio_if_ops[pktio_if]->name, pktio_type))
			continue;

		ret = pktio_if_ops[pktio_if]->open(hdl, pktio_entry, if_name,
						   pool);
		if (!ret)
			break;
	}

	if (ret != 0) {
		pktio_entry->s.state = PKTIO_STATE_FREE;
		unlock_entry(pktio_entry);
		ODP_ERR("Unable to init any I/O type.\n");
		return ODP_PKTIO_INVALID;
	}

	snprintf(pktio_entry->s.name,
		 sizeof(pktio_entry->s.name), "%s", if_name);
	snprintf(pktio_entry->s.full_name,
		 sizeof(pktio_entry->s.full_name), "%s", name);
	pktio_entry->s.state = PKTIO_STATE_OPENED;
	pktio_entry->s.ops = pktio_if_ops[pktio_if];
	unlock_entry(pktio_entry);

	return hdl;
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

static const char *driver_name(odp_pktio_t hdl)
{
	pktio_entry_t *entry;

	if (hdl != ODP_PKTIO_INVALID) {
		entry = get_pktio_entry(hdl);
		return entry->s.ops->name;
	}

	return "bad handle";
}

odp_pktio_t odp_pktio_open(const char *name, odp_pool_t pool,
			   const odp_pktio_param_t *param)
{
	odp_pktio_t hdl;
	odp_pktio_param_t default_param;

	if (param == NULL) {
		odp_pktio_param_init(&default_param);
		param = &default_param;
	}

	ODP_ASSERT(pool_type_is_packet(pool));

	hdl = odp_pktio_lookup(name);
	if (hdl != ODP_PKTIO_INVALID) {
		/* interface is already open */
		__odp_errno = EEXIST;
		return ODP_PKTIO_INVALID;
	}

	odp_spinlock_lock(&pktio_tbl->lock);
	hdl = setup_pktio_entry(name, pool, param);
	odp_spinlock_unlock(&pktio_tbl->lock);

	ODP_DBG("interface: %s, driver: %s\n", name, driver_name(hdl));

	return hdl;
}

static int _pktio_close(pktio_entry_t *entry)
{
	int ret;
	int state = entry->s.state;

	if (state != PKTIO_STATE_OPENED &&
	    state != PKTIO_STATE_STOPPED &&
	    state != PKTIO_STATE_STOP_PENDING)
		return -1;

	ret = entry->s.ops->close(entry);
	if (ret)
		return -1;

	if (state == PKTIO_STATE_STOP_PENDING)
		entry->s.state = PKTIO_STATE_CLOSE_PENDING;
	else
		entry->s.state = PKTIO_STATE_FREE;

	return 0;
}

static void destroy_in_queues(pktio_entry_t *entry, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		if (entry->s.in_queue[i].queue != ODP_QUEUE_INVALID) {
			odp_queue_destroy(entry->s.in_queue[i].queue);
			entry->s.in_queue[i].queue = ODP_QUEUE_INVALID;
		}
	}
}

static void destroy_out_queues(pktio_entry_t *entry, int num)
{
	int i, rc;

	for (i = 0; i < num; i++) {
		if (entry->s.out_queue[i].queue != ODP_QUEUE_INVALID) {
			rc = odp_queue_destroy(entry->s.out_queue[i].queue);
			ODP_ASSERT(rc == 0);
			entry->s.out_queue[i].queue = ODP_QUEUE_INVALID;
		}
	}
}

static void flush_in_queues(pktio_entry_t *entry)
{
	odp_pktin_mode_t mode;
	int num, i;
	int max_pkts = 16;
	odp_packet_t packets[max_pkts];

	mode = entry->s.param.in_mode;
	num  = entry->s.num_in_queue;

	if (mode == ODP_PKTIN_MODE_DIRECT) {
		for (i = 0; i < num; i++) {
			int ret;
			odp_pktin_queue_t pktin = entry->s.in_queue[i].pktin;

			while ((ret = odp_pktin_recv(pktin, packets,
						     max_pkts))) {
				if (ret < 0) {
					ODP_ERR("Queue flush failed\n");
					return;
				}

				odp_packet_free_multi(packets, ret);
			}
		}
	}
}

int odp_pktio_close(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	int res;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		ODP_ERR("Bad handle\n");
		return -1;
	}

	if (entry->s.state == PKTIO_STATE_STARTED) {
		ODP_DBG("Missing odp_pktio_stop() before close.\n");
		return -1;
	}

	if (entry->s.state == PKTIO_STATE_STOPPED)
		flush_in_queues(entry);

	lock_entry(entry);

	destroy_in_queues(entry, entry->s.num_in_queue);
	destroy_out_queues(entry, entry->s.num_out_queue);

	entry->s.num_in_queue  = 0;
	entry->s.num_out_queue = 0;

	odp_spinlock_lock(&pktio_tbl->lock);
	res = _pktio_close(entry);
	odp_spinlock_unlock(&pktio_tbl->lock);
	if (res)
		ODP_ABORT("unable to close pktio\n");

	unlock_entry(entry);

	ODP_DBG("interface: %s\n", entry->s.name);

	return 0;
}

int odp_pktio_config(odp_pktio_t hdl, const odp_pktio_config_t *config)
{
	pktio_entry_t *entry;
	odp_pktio_capability_t capa;
	odp_pktio_config_t default_config;
	int res = 0;

	entry = get_pktio_entry(hdl);
	if (!entry) {
		ODP_ERR("Bad handle\n");
		return -1;
	}

	if (config == NULL) {
		odp_pktio_config_init(&default_config);
		config = &default_config;
	}

	if (odp_pktio_capability(hdl, &capa))
		return -1;

	/* Check config for invalid values */
	if (config->pktin.all_bits & ~capa.config.pktin.all_bits) {
		ODP_ERR("Unsupported input configuration option\n");
		return -1;
	}
	if (config->pktout.all_bits & ~capa.config.pktout.all_bits) {
		ODP_ERR("Unsupported output configuration option\n");
		return -1;
	}

	if (config->enable_loop && !capa.config.enable_loop) {
		ODP_ERR("Loopback mode not supported\n");
		return -1;
	}

	lock_entry(entry);
	if (entry->s.state == PKTIO_STATE_STARTED) {
		unlock_entry(entry);
		ODP_DBG("pktio %s: not stopped\n", entry->s.name);
		return -1;
	}

	entry->s.config = *config;

	entry->s.in_chksums.all_chksum = 0;
	entry->s.in_chksums.chksum.ipv4 = config->pktin.bit.ipv4_chksum;
	entry->s.in_chksums.chksum.tcp = config->pktin.bit.tcp_chksum;
	entry->s.in_chksums.chksum.udp = config->pktin.bit.udp_chksum;
	entry->s.in_chksums.chksum.sctp = config->pktin.bit.sctp_chksum;

	if (entry->s.ops->config)
		res = entry->s.ops->config(entry, config);

	unlock_entry(entry);

	return res;
}

int odp_pktio_start(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	odp_pktin_mode_t mode;
	int res = 0;

	entry = get_pktio_entry(hdl);
	if (!entry) {
		ODP_ERR("Bad handle\n");
		return -1;
	}

	lock_entry(entry);
	if (entry->s.state == PKTIO_STATE_STARTED) {
		unlock_entry(entry);
		ODP_ERR("Already started\n");
		return -1;
	}
	if (entry->s.ops->start)
		res = entry->s.ops->start(entry);
	if (!res)
		entry->s.state = PKTIO_STATE_STARTED;

	unlock_entry(entry);

	mode = entry->s.param.in_mode;

	if (mode == ODP_PKTIN_MODE_SCHED) {
		unsigned i;
		unsigned num = entry->s.num_in_queue;
		int index[num];
		odp_queue_t odpq[num];

		for (i = 0; i < num; i++) {
			index[i] = i;
			odpq[i] = entry->s.in_queue[i].queue;

			if (entry->s.in_queue[i].queue == ODP_QUEUE_INVALID) {
				ODP_ERR("No input queue\n");
				return -1;
			}
		}

		sched_fn->pktio_start(odp_pktio_index(hdl), num, index, odpq);
	}

	ODP_DBG("interface: %s, input queues: %u, output queues: %u\n",
		entry->s.name, entry->s.num_in_queue, entry->s.num_out_queue);

	if (_ODP_PCAPNG) {
		if (_odp_pcapng_start(entry))
			ODP_ERR("pcapng start failed, won't capture\n");
	}

	return res;
}

static int _pktio_stop(pktio_entry_t *entry)
{
	int res = 0;
	odp_pktin_mode_t mode = entry->s.param.in_mode;

	if (entry->s.state != PKTIO_STATE_STARTED) {
		ODP_ERR("Not started\n");
		return -1;
	}

	if (entry->s.ops->stop)
		res = entry->s.ops->stop(entry);

	if (res)
		return -1;

	if (mode == ODP_PKTIN_MODE_SCHED)
		entry->s.state = PKTIO_STATE_STOP_PENDING;
	else
		entry->s.state = PKTIO_STATE_STOPPED;

	if (_ODP_PCAPNG)
		_odp_pcapng_stop(entry);

	return res;
}

int odp_pktio_stop(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	int res;

	entry = get_pktio_entry(hdl);
	if (!entry) {
		ODP_ERR("Bad handle\n");
		return -1;
	}

	lock_entry(entry);
	res = _pktio_stop(entry);
	unlock_entry(entry);

	ODP_DBG("interface: %s\n", entry->s.name);

	return res;
}

odp_pktio_t odp_pktio_lookup(const char *name)
{
	odp_pktio_t hdl = ODP_PKTIO_INVALID;
	pktio_entry_t *entry;
	const char *ifname;
	int i;

	ifname = strip_pktio_type(name, NULL);

	odp_spinlock_lock(&pktio_tbl->lock);

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		entry = pktio_entry_by_index(i);
		if (!entry || is_free(entry))
			continue;

		lock_entry(entry);

		if (entry->s.state >= PKTIO_STATE_ACTIVE &&
		    strncmp(entry->s.name, ifname, sizeof(entry->s.name)) == 0)
			hdl = _odp_cast_scalar(odp_pktio_t, i + 1);

		unlock_entry(entry);

		if (hdl != ODP_PKTIO_INVALID)
			break;
	}

	odp_spinlock_unlock(&pktio_tbl->lock);

	return hdl;
}

static inline int pktin_recv_buf(pktio_entry_t *entry, int pktin_index,
				 odp_buffer_hdr_t *buffer_hdrs[], int num)
{
	odp_packet_t pkt;
	odp_packet_t packets[num];
	odp_packet_hdr_t *pkt_hdr;
	odp_buffer_hdr_t *buf_hdr;
	int i, pkts, num_rx, num_ev, num_dst;
	odp_queue_t cur_queue;
	odp_event_t ev[num];
	odp_queue_t dst[num];
	int dst_idx[num];

	num_rx = 0;
	num_dst = 0;
	num_ev = 0;

	/* Some compilers need this dummy initialization */
	cur_queue = ODP_QUEUE_INVALID;

	pkts = entry->s.ops->recv(entry, pktin_index, packets, num);

	for (i = 0; i < pkts; i++) {
		pkt = packets[i];
		pkt_hdr = packet_hdr(pkt);
		buf_hdr = packet_to_buf_hdr(pkt);

		if (odp_unlikely(pkt_hdr->p.input_flags.dst_queue)) {
			/* Sort events for enqueue multi operation(s) */
			if (odp_unlikely(num_dst == 0)) {
				num_dst = 1;
				cur_queue = pkt_hdr->dst_queue;
				dst[0] = cur_queue;
				dst_idx[0] = 0;
			}

			ev[num_ev] = odp_packet_to_event(pkt);

			if (cur_queue != pkt_hdr->dst_queue) {
				cur_queue = pkt_hdr->dst_queue;
				dst[num_dst] = cur_queue;
				dst_idx[num_dst] = num_ev;
				num_dst++;
			}

			num_ev++;
			continue;
		}
		buffer_hdrs[num_rx++] = buf_hdr;
	}

	/* Optimization for the common case */
	if (odp_likely(num_dst == 0))
		return num_rx;

	for (i = 0; i < num_dst; i++) {
		int num_enq, ret;
		int idx = dst_idx[i];

		if (i == (num_dst - 1))
			num_enq = num_ev - idx;
		else
			num_enq = dst_idx[i + 1] - idx;

		ret = odp_queue_enq_multi(dst[i], &ev[idx], num_enq);

		if (ret < 0)
			ret = 0;

		if (ret < num_enq)
			odp_event_free_multi(&ev[idx + ret], num_enq - ret);
	}

	return num_rx;
}

static int pktout_enqueue(odp_queue_t queue, odp_buffer_hdr_t *buf_hdr)
{
	odp_packet_t pkt = packet_from_buf_hdr(buf_hdr);
	int len = 1;
	int nbr;

	if (sched_fn->ord_enq_multi(queue, (void **)buf_hdr, len, &nbr))
		return (nbr == len ? 0 : -1);

	nbr = odp_pktout_send(queue_fn->get_pktout(queue), &pkt, len);
	return (nbr == len ? 0 : -1);
}

static int pktout_enq_multi(odp_queue_t queue, odp_buffer_hdr_t *buf_hdr[],
			    int num)
{
	odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
	int nbr;
	int i;

	if (sched_fn->ord_enq_multi(queue, (void **)buf_hdr, num, &nbr))
		return nbr;

	for (i = 0; i < num; ++i)
		pkt_tbl[i] = packet_from_buf_hdr(buf_hdr[i]);

	nbr = odp_pktout_send(queue_fn->get_pktout(queue), pkt_tbl, num);
	return nbr;
}

static odp_buffer_hdr_t *pktin_dequeue(odp_queue_t queue)
{
	odp_buffer_hdr_t *buf_hdr;
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	int pkts;
	odp_pktin_queue_t pktin_queue = queue_fn->get_pktin(queue);
	odp_pktio_t pktio = pktin_queue.pktio;
	int pktin_index   = pktin_queue.index;
	pktio_entry_t *entry = get_pktio_entry(pktio);

	if (queue_fn->orig_deq_multi(queue, &buf_hdr, 1) == 1)
		return buf_hdr;

	pkts = pktin_recv_buf(entry, pktin_index, hdr_tbl, QUEUE_MULTI_MAX);

	if (pkts <= 0)
		return NULL;

	if (pkts > 1) {
		int num_enq;
		int num = pkts - 1;

		num_enq = odp_queue_enq_multi(queue,
					      (odp_event_t *)&hdr_tbl[1], num);

		if (odp_unlikely(num_enq < num)) {
			if (odp_unlikely(num_enq < 0))
				num_enq = 0;

			ODP_DBG("Interface %s dropped %i packets\n",
				entry->s.name, num - num_enq);
			buffer_free_multi(&hdr_tbl[num_enq + 1], num - num_enq);
		}
	}

	buf_hdr = hdr_tbl[0];
	return buf_hdr;
}

static int pktin_deq_multi(odp_queue_t queue, odp_buffer_hdr_t *buf_hdr[],
			   int num)
{
	int nbr;
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	int pkts, i, j;
	odp_pktin_queue_t pktin_queue = queue_fn->get_pktin(queue);
	odp_pktio_t pktio = pktin_queue.pktio;
	int pktin_index   = pktin_queue.index;
	pktio_entry_t *entry = get_pktio_entry(pktio);

	nbr = queue_fn->orig_deq_multi(queue, buf_hdr, num);
	if (odp_unlikely(nbr > num))
		ODP_ABORT("queue_deq_multi req: %d, returned %d\n", num, nbr);

	/** queue already has number of requsted buffers,
	 *  do not do receive in that case.
	 */
	if (nbr == num)
		return nbr;

	pkts = pktin_recv_buf(entry, pktin_index, hdr_tbl, QUEUE_MULTI_MAX);

	if (pkts <= 0)
		return nbr;

	for (i = 0; i < pkts && nbr < num; i++, nbr++)
		buf_hdr[nbr] = hdr_tbl[i];

	/* Queue the rest for later */
	for (j = 0; i < pkts; i++, j++)
		hdr_tbl[j] = hdr_tbl[i];

	if (j) {
		int num_enq;

		num_enq = odp_queue_enq_multi(queue, (odp_event_t *)hdr_tbl, j);

		if (odp_unlikely(num_enq < j)) {
			if (odp_unlikely(num_enq < 0))
				num_enq = 0;

			ODP_DBG("Interface %s dropped %i packets\n",
				entry->s.name, j - num_enq);
			buffer_free_multi(&buf_hdr[num_enq], j - num_enq);
		}
	}

	return nbr;
}

int sched_cb_pktin_poll_one(int pktio_index,
			    int rx_queue,
			    odp_event_t evt_tbl[QUEUE_MULTI_MAX])
{
	int num_rx, num_pkts, i;
	pktio_entry_t *entry = pktio_entry_by_index(pktio_index);
	odp_packet_t pkt;
	odp_packet_hdr_t *pkt_hdr;
	odp_buffer_hdr_t *buf_hdr;
	odp_packet_t packets[QUEUE_MULTI_MAX];
	odp_queue_t queue;

	if (odp_unlikely(entry->s.state != PKTIO_STATE_STARTED)) {
		if (entry->s.state < PKTIO_STATE_ACTIVE ||
		    entry->s.state == PKTIO_STATE_STOP_PENDING)
			return -1;

		ODP_DBG("interface not started\n");
		return 0;
	}

	ODP_ASSERT((unsigned)rx_queue < entry->s.num_in_queue);
	num_pkts = entry->s.ops->recv(entry, rx_queue,
				      packets, QUEUE_MULTI_MAX);

	num_rx = 0;
	for (i = 0; i < num_pkts; i++) {
		pkt = packets[i];
		pkt_hdr = packet_hdr(pkt);
		if (odp_unlikely(pkt_hdr->p.input_flags.dst_queue)) {
			int num_enq;

			queue = pkt_hdr->dst_queue;
			buf_hdr = packet_to_buf_hdr(pkt);
			num_enq = odp_queue_enq_multi(queue,
						      (odp_event_t *)&buf_hdr,
						      1);
			if (num_enq < 0) {
				/* Queue full? */
				odp_packet_free(pkt);
				__atomic_fetch_add(&entry->s.stats.in_discards,
						   1,
						   __ATOMIC_RELAXED);
			}
		} else {
			evt_tbl[num_rx++] = odp_packet_to_event(pkt);
		}
	}
	return num_rx;
}

int sched_cb_pktin_poll(int pktio_index, int pktin_index,
			odp_buffer_hdr_t *hdr_tbl[], int num)
{
	pktio_entry_t *entry = pktio_entry_by_index(pktio_index);
	int state = entry->s.state;

	if (odp_unlikely(state != PKTIO_STATE_STARTED)) {
		if (state < PKTIO_STATE_ACTIVE ||
		    state == PKTIO_STATE_STOP_PENDING)
			return -1;

		ODP_DBG("Interface %s not started\n", entry->s.name);
		return 0;
	}

	return pktin_recv_buf(entry, pktin_index, hdr_tbl, num);
}

void sched_cb_pktio_stop_finalize(int pktio_index)
{
	int state;
	pktio_entry_t *entry = pktio_entry_by_index(pktio_index);

	lock_entry(entry);

	state = entry->s.state;

	if (state != PKTIO_STATE_STOP_PENDING &&
	    state != PKTIO_STATE_CLOSE_PENDING) {
		unlock_entry(entry);
		ODP_ERR("Not in a pending state %i\n", state);
		return;
	}

	if (state == PKTIO_STATE_STOP_PENDING)
		entry->s.state = PKTIO_STATE_STOPPED;
	else
		entry->s.state = PKTIO_STATE_FREE;

	unlock_entry(entry);
}

static inline uint32_t pktio_mtu(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	uint32_t ret = 0;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", hdl);
		return 0;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return 0;
	}

	if (entry->s.ops->mtu_get)
		ret = entry->s.ops->mtu_get(entry);

	unlock_entry(entry);
	return ret;
}

uint32_t ODP_DEPRECATE(odp_pktio_mtu)(odp_pktio_t pktio)
{
	return pktio_mtu(pktio);
}

uint32_t odp_pktin_maxlen(odp_pktio_t pktio)
{
	return pktio_mtu(pktio);
}

uint32_t odp_pktout_maxlen(odp_pktio_t pktio)
{
	return pktio_mtu(pktio);
}

int odp_pktio_promisc_mode_set(odp_pktio_t hdl, odp_bool_t enable)
{
	pktio_entry_t *entry;
	int ret = -1;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", hdl);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}
	if (entry->s.state == PKTIO_STATE_STARTED) {
		unlock_entry(entry);
		return -1;
	}

	if (entry->s.ops->promisc_mode_set)
		ret = entry->s.ops->promisc_mode_set(entry, enable);

	unlock_entry(entry);
	return ret;
}

int odp_pktio_promisc_mode(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	int ret = -1;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", hdl);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	if (entry->s.ops->promisc_mode_get)
		ret = entry->s.ops->promisc_mode_get(entry);
	unlock_entry(entry);

	return ret;
}

int odp_pktio_mac_addr(odp_pktio_t hdl, void *mac_addr, int addr_size)
{
	pktio_entry_t *entry;
	int ret = ETH_ALEN;

	if (addr_size < ETH_ALEN) {
		/* Output buffer too small */
		return -1;
	}

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", hdl);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	if (entry->s.ops->mac_get) {
		ret = entry->s.ops->mac_get(entry, mac_addr);
	} else {
		ODP_DBG("pktio does not support mac addr get\n");
		ret = -1;
	}
	unlock_entry(entry);

	return ret;
}

int odp_pktio_mac_addr_set(odp_pktio_t hdl, const void *mac_addr, int addr_size)
{
	pktio_entry_t *entry;
	int ret = -1;

	if (addr_size < ETH_ALEN) {
		/* Input buffer too small */
		return -1;
	}

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", hdl);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	if (entry->s.state == PKTIO_STATE_STARTED) {
		unlock_entry(entry);
		return -1;
	}

	if (entry->s.ops->mac_set)
		ret = entry->s.ops->mac_set(entry, mac_addr);

	unlock_entry(entry);
	return ret;
}

int odp_pktio_link_status(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	int ret = -1;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", hdl);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	if (entry->s.ops->link_status)
		ret = entry->s.ops->link_status(entry);
	unlock_entry(entry);

	return ret;
}

void odp_pktio_param_init(odp_pktio_param_t *params)
{
	memset(params, 0, sizeof(odp_pktio_param_t));
	params->in_mode  = ODP_PKTIN_MODE_DIRECT;
	params->out_mode = ODP_PKTOUT_MODE_DIRECT;
}

void odp_pktin_queue_param_init(odp_pktin_queue_param_t *param)
{
	memset(param, 0, sizeof(odp_pktin_queue_param_t));
	param->op_mode = ODP_PKTIO_OP_MT;
	param->num_queues = 1;
	/* no need to choose queue type since pktin mode defines it */
	odp_queue_param_init(&param->queue_param);
}

void odp_pktout_queue_param_init(odp_pktout_queue_param_t *param)
{
	memset(param, 0, sizeof(odp_pktout_queue_param_t));
	param->op_mode = ODP_PKTIO_OP_MT;
	param->num_queues = 1;
}

void odp_pktio_config_init(odp_pktio_config_t *config)
{
	memset(config, 0, sizeof(odp_pktio_config_t));

	config->parser.layer = ODP_PROTO_LAYER_ALL;
}

int odp_pktio_info(odp_pktio_t hdl, odp_pktio_info_t *info)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(hdl);

	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", hdl);
		return -1;
	}

	memset(info, 0, sizeof(odp_pktio_info_t));
	info->name = entry->s.full_name;
	info->drv_name = entry->s.ops->name;
	info->pool = entry->s.pool;
	memcpy(&info->param, &entry->s.param, sizeof(odp_pktio_param_t));

	return 0;
}

uint64_t odp_pktin_ts_res(odp_pktio_t hdl)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(hdl);

	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", hdl);
		return 0;
	}

	if (entry->s.ops->pktin_ts_res)
		return entry->s.ops->pktin_ts_res(entry);

	return odp_time_global_res();
}

odp_time_t odp_pktin_ts_from_ns(odp_pktio_t hdl, uint64_t ns)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(hdl);

	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", hdl);
		return ODP_TIME_NULL;
	}

	if (entry->s.ops->pktin_ts_from_ns)
		return entry->s.ops->pktin_ts_from_ns(entry, ns);

	return odp_time_global_from_ns(ns);
}

void odp_pktio_print(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	odp_pktio_capability_t capa;
	uint8_t addr[ETH_ALEN];
	int max_len = 512;
	char str[max_len];
	int len = 0;
	int n = max_len - 1;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", hdl);
		return;
	}

	len += snprintf(&str[len], n - len,
			"pktio\n");
	len += snprintf(&str[len], n - len,
			"  name              %s\n", entry->s.name);
	len += snprintf(&str[len], n - len,
			"  type              %s\n", entry->s.ops->name);
	len += snprintf(&str[len], n - len,
			"  index             %i\n", odp_pktio_index(hdl));
	len += snprintf(&str[len], n - len,
			"  handle (u64)      %" PRIu64 "\n",
			odp_pktio_to_u64(hdl));
	len += snprintf(&str[len], n - len,
			"  state             %s\n",
			entry->s.state ==  PKTIO_STATE_STARTED ? "start" :
		       (entry->s.state ==  PKTIO_STATE_STOPPED ? "stop" :
		       (entry->s.state ==  PKTIO_STATE_STOP_PENDING ?
			"stop pending" :
		       (entry->s.state ==  PKTIO_STATE_OPENED ? "opened" :
								"unknown"))));
	memset(addr, 0, sizeof(addr));
	odp_pktio_mac_addr(hdl, addr, ETH_ALEN);
	len += snprintf(&str[len], n - len,
			"  mac               %02x:%02x:%02x:%02x:%02x:%02x\n",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	len += snprintf(&str[len], n - len,
			"  pktin maxlen      %" PRIu32 "\n",
			odp_pktin_maxlen(hdl));
	len += snprintf(&str[len], n - len,
			"  pktout maxlen     %" PRIu32 "\n",
			odp_pktout_maxlen(hdl));
	len += snprintf(&str[len], n - len,
			"  promisc           %s\n",
			odp_pktio_promisc_mode(hdl) ? "yes" : "no");

	if (!odp_pktio_capability(hdl, &capa)) {
		len += snprintf(&str[len], n - len, "  max input queues  %u\n",
				capa.max_input_queues);
		len += snprintf(&str[len], n - len, "  max output queues %u\n",
				capa.max_output_queues);
	}

	str[len] = '\0';

	ODP_PRINT("\n%s", str);

	if (entry->s.ops->print)
		entry->s.ops->print(entry);

	ODP_PRINT("\n");
}

int _odp_pktio_term_global(void)
{
	int ret = 0;
	int i;
	int pktio_if;

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		pktio_entry_t *pktio_entry;

		pktio_entry = &pktio_tbl->entries[i];

		if (is_free(pktio_entry))
			continue;

		lock_entry(pktio_entry);
		if (pktio_entry->s.state == PKTIO_STATE_STARTED) {
			ret = _pktio_stop(pktio_entry);
			if (ret)
				ODP_ABORT("unable to stop pktio %s\n",
					  pktio_entry->s.name);
		}

		if (pktio_entry->s.state != PKTIO_STATE_CLOSE_PENDING)
			ret = _pktio_close(pktio_entry);
		if (ret)
			ODP_ABORT("unable to close pktio %s\n",
				  pktio_entry->s.name);
		unlock_entry(pktio_entry);
	}

	for (pktio_if = 0; pktio_if_ops[pktio_if]; ++pktio_if) {
		if (pktio_if_ops[pktio_if]->term)
			if (pktio_if_ops[pktio_if]->term())
				ODP_ABORT("failed to terminate pktio type %d",
					  pktio_if);
	}

	if (_ODP_PCAPNG) {
		ret = _odp_pcapng_term_global();
		if (ret)
			ODP_ERR("Failed to terminate pcapng\n");
	}

	ret = odp_shm_free(odp_shm_lookup("_odp_pktio_entries"));
	if (ret != 0)
		ODP_ERR("shm free failed for _odp_pktio_entries");

	return ret;
}

static
int single_capability(odp_pktio_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_pktio_capability_t));
	capa->max_input_queues  = 1;
	capa->max_output_queues = 1;
	capa->set_op.op.promisc_mode = 1;

	return 0;
}

int odp_pktio_capability(odp_pktio_t pktio, odp_pktio_capability_t *capa)
{
	pktio_entry_t *entry;
	int ret;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	if (entry->s.ops->capability)
		ret = entry->s.ops->capability(entry, capa);
	else
		ret = single_capability(capa);

	/* The same parser is used for all pktios */
	if (ret == 0)
		capa->config.parser.layer = ODP_PROTO_LAYER_ALL;

	return ret;
}

unsigned odp_pktio_max_index(void)
{
	return ODP_CONFIG_PKTIO_ENTRIES - 1;
}

int odp_pktio_stats(odp_pktio_t pktio,
		    odp_pktio_stats_t *stats)
{
	pktio_entry_t *entry;
	int ret = -1;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	if (entry->s.ops->stats)
		ret = entry->s.ops->stats(entry, stats);
	unlock_entry(entry);

	return ret;
}

int odp_pktio_stats_reset(odp_pktio_t pktio)
{
	pktio_entry_t *entry;
	int ret = -1;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	if (entry->s.ops->stats)
		ret = entry->s.ops->stats_reset(entry);
	unlock_entry(entry);

	return ret;
}

int odp_pktin_queue_config(odp_pktio_t pktio,
			   const odp_pktin_queue_param_t *param)
{
	pktio_entry_t *entry;
	odp_pktin_mode_t mode;
	odp_pktio_capability_t capa;
	unsigned num_queues;
	unsigned i;
	int rc;
	odp_queue_t queue;
	odp_pktin_queue_param_t default_param;

	if (param == NULL) {
		odp_pktin_queue_param_init(&default_param);
		param = &default_param;
	}

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	if (entry->s.state == PKTIO_STATE_STARTED) {
		ODP_DBG("pktio %s: not stopped\n", entry->s.name);
		return -1;
	}

	mode = entry->s.param.in_mode;

	/* Ignore the call when packet input is disabled. */
	if (mode == ODP_PKTIN_MODE_DISABLED)
		return 0;

	if (!param->classifier_enable && param->num_queues == 0) {
		ODP_DBG("invalid num_queues for operation mode\n");
		return -1;
	}

	num_queues = param->classifier_enable ? 1 : param->num_queues;

	rc = odp_pktio_capability(pktio, &capa);
	if (rc) {
		ODP_DBG("pktio %s: unable to read capabilities\n",
			entry->s.name);
		return -1;
	}

	pktio_cls_enabled_set(entry, param->classifier_enable);

	if (num_queues > capa.max_input_queues) {
		ODP_DBG("pktio %s: too many input queues\n", entry->s.name);
		return -1;
	}

	/* If re-configuring, destroy old queues */
	if (entry->s.num_in_queue)
		destroy_in_queues(entry, entry->s.num_in_queue);

	for (i = 0; i < num_queues; i++) {
		if (mode == ODP_PKTIN_MODE_QUEUE ||
		    mode == ODP_PKTIN_MODE_SCHED) {
			odp_queue_param_t queue_param;
			char name[ODP_QUEUE_NAME_LEN];
			int pktio_id = odp_pktio_index(pktio);
			odp_pktin_queue_param_ovr_t *queue_param_ovr = NULL;

			if (param->queue_param_ovr)
				queue_param_ovr = param->queue_param_ovr + i;

			snprintf(name, sizeof(name), "odp-pktin-%i-%i",
				 pktio_id, i);

			if (param->classifier_enable) {
				odp_queue_param_init(&queue_param);
			} else {
				memcpy(&queue_param, &param->queue_param,
				       sizeof(odp_queue_param_t));
				if (queue_param_ovr)
					queue_param.sched.group =
						queue_param_ovr->group;
			}

			queue_param.type = ODP_QUEUE_TYPE_PLAIN;

			if (mode == ODP_PKTIN_MODE_SCHED)
				queue_param.type = ODP_QUEUE_TYPE_SCHED;

			queue = odp_queue_create(name, &queue_param);

			if (queue == ODP_QUEUE_INVALID) {
				ODP_DBG("pktio %s: event queue create failed\n",
					entry->s.name);
				destroy_in_queues(entry, i + 1);
				return -1;
			}

			if (mode == ODP_PKTIN_MODE_QUEUE) {
				queue_fn->set_pktin(queue, pktio, i);
				queue_fn->set_enq_deq_fn(queue,
							 NULL,
							 NULL,
							 pktin_dequeue,
							 pktin_deq_multi);
			}

			entry->s.in_queue[i].queue = queue;

		} else {
			entry->s.in_queue[i].queue = ODP_QUEUE_INVALID;
		}

		entry->s.in_queue[i].pktin.index = i;
		entry->s.in_queue[i].pktin.pktio = entry->s.handle;
	}

	entry->s.num_in_queue = num_queues;

	if (entry->s.ops->input_queues_config)
		return entry->s.ops->input_queues_config(entry, param);

	return 0;
}

int odp_pktout_queue_config(odp_pktio_t pktio,
			    const odp_pktout_queue_param_t *param)
{
	pktio_entry_t *entry;
	odp_pktout_mode_t mode;
	odp_pktio_capability_t capa;
	unsigned num_queues;
	unsigned i;
	int rc;
	odp_pktout_queue_param_t default_param;

	if (param == NULL) {
		odp_pktout_queue_param_init(&default_param);
		param = &default_param;
	}

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	if (entry->s.state == PKTIO_STATE_STARTED) {
		ODP_DBG("pktio %s: not stopped\n", entry->s.name);
		return -1;
	}

	mode = entry->s.param.out_mode;

	/* Ignore the call when packet output is disabled, or routed through
	 * traffic manager. */
	if (mode == ODP_PKTOUT_MODE_DISABLED || mode == ODP_PKTOUT_MODE_TM)
		return 0;

	if (mode != ODP_PKTOUT_MODE_DIRECT && mode != ODP_PKTOUT_MODE_QUEUE) {
		ODP_DBG("pktio %s: bad packet output mode\n", entry->s.name);
		return -1;
	}

	num_queues = param->num_queues;

	if (num_queues == 0) {
		ODP_DBG("pktio %s: zero output queues\n", entry->s.name);
		return -1;
	}

	rc = odp_pktio_capability(pktio, &capa);
	if (rc) {
		ODP_DBG("pktio %s: unable to read capabilities\n",
			entry->s.name);
		return -1;
	}

	if (num_queues > capa.max_output_queues) {
		ODP_DBG("pktio %s: too many output queues\n", entry->s.name);
		return -1;
	}

	/* If re-configuring, destroy old queues */
	if (entry->s.num_out_queue) {
		destroy_out_queues(entry, entry->s.num_out_queue);
		entry->s.num_out_queue = 0;
	}

	init_out_queues(entry);

	for (i = 0; i < num_queues; i++) {
		entry->s.out_queue[i].pktout.index = i;
		entry->s.out_queue[i].pktout.pktio = pktio;
	}

	entry->s.num_out_queue = num_queues;

	if (mode == ODP_PKTOUT_MODE_QUEUE) {
		for (i = 0; i < num_queues; i++) {
			odp_queue_t queue;
			odp_queue_param_t queue_param;
			char name[ODP_QUEUE_NAME_LEN];
			int pktio_id = odp_pktio_index(pktio);

			snprintf(name, sizeof(name), "odp-pktout-%i-%i",
				 pktio_id, i);

			odp_queue_param_init(&queue_param);
			/* Application cannot dequeue from the queue */
			queue_param.deq_mode = ODP_QUEUE_OP_DISABLED;

			queue = odp_queue_create(name, &queue_param);

			if (queue == ODP_QUEUE_INVALID) {
				ODP_DBG("pktout %s: event queue create failed\n",
					entry->s.name);
				destroy_out_queues(entry, i + 1);
				return -1;
			}

			queue_fn->set_pktout(queue, pktio, i);

			/* Override default enqueue / dequeue functions */
			queue_fn->set_enq_deq_fn(queue,
						 pktout_enqueue,
						 pktout_enq_multi,
						 NULL,
						 NULL);

			entry->s.out_queue[i].queue = queue;
		}
	}

	if (entry->s.ops->output_queues_config)
		return entry->s.ops->output_queues_config(entry, param);

	return 0;
}

int odp_pktin_event_queue(odp_pktio_t pktio, odp_queue_t queues[], int num)
{
	pktio_entry_t *entry;
	odp_pktin_mode_t mode;
	int i;
	int num_queues;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	if (num < 0) {
		ODP_DBG("Bad param: num %i\n", num);
		return -1;
	}

	mode = entry->s.param.in_mode;

	if (mode == ODP_PKTIN_MODE_DISABLED)
		return 0;

	if (mode != ODP_PKTIN_MODE_QUEUE &&
	    mode != ODP_PKTIN_MODE_SCHED)
		return -1;

	num_queues = entry->s.num_in_queue;

	if (queues) {
		if (num_queues < num)
			num = num_queues;

		for (i = 0; i < num; i++)
			queues[i] = entry->s.in_queue[i].queue;
	}

	return num_queues;
}

int odp_pktin_queue(odp_pktio_t pktio, odp_pktin_queue_t queues[], int num)
{
	pktio_entry_t *entry;
	odp_pktin_mode_t mode;
	int i;
	int num_queues;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	if (num < 0) {
		ODP_DBG("Bad param: num %i\n", num);
		return -1;
	}

	mode = entry->s.param.in_mode;

	if (mode == ODP_PKTIN_MODE_DISABLED)
		return 0;

	if (mode != ODP_PKTIN_MODE_DIRECT)
		return -1;

	num_queues = entry->s.num_in_queue;

	if (queues) {
		if (num_queues < num)
			num = num_queues;

		for (i = 0; i < num; i++)
			queues[i] = entry->s.in_queue[i].pktin;
	}

	return num_queues;
}

int odp_pktout_event_queue(odp_pktio_t pktio, odp_queue_t queues[], int num)
{
	pktio_entry_t *entry;
	odp_pktout_mode_t mode;
	int i;
	int num_queues;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	mode = entry->s.param.out_mode;

	if (mode == ODP_PKTOUT_MODE_DISABLED)
		return 0;

	if (mode != ODP_PKTOUT_MODE_QUEUE)
		return -1;

	num_queues = entry->s.num_out_queue;

	if (queues && num > 0) {
		for (i = 0; i < num && i < num_queues; i++)
			queues[i] = entry->s.out_queue[i].queue;
	}

	return num_queues;
}

int odp_pktout_queue(odp_pktio_t pktio, odp_pktout_queue_t queues[], int num)
{
	pktio_entry_t *entry;
	odp_pktout_mode_t mode;
	int i;
	int num_queues;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	mode = entry->s.param.out_mode;

	if (mode == ODP_PKTOUT_MODE_DISABLED)
		return 0;

	if (mode != ODP_PKTOUT_MODE_DIRECT)
		return -1;

	num_queues = entry->s.num_out_queue;

	if (queues && num > 0) {
		for (i = 0; i < num && i < num_queues; i++)
			queues[i] = entry->s.out_queue[i].pktout;
	}

	return num_queues;
}

static inline void _odp_dump_pcapng_pkts(pktio_entry_t *entry, int qidx,
					 const odp_packet_t packets[], int num)
{
	if (odp_unlikely(entry->s.pcapng.state[qidx] == PCAPNG_WR_PKT))
		_odp_pcapng_write_pkts(entry, qidx, packets, num);
}

int odp_pktin_recv(odp_pktin_queue_t queue, odp_packet_t packets[], int num)
{
	pktio_entry_t *entry;
	odp_pktio_t pktio = queue.pktio;
	int ret;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	ret = entry->s.ops->recv(entry, queue.index, packets, num);
	if (_ODP_PCAPNG)
		_odp_dump_pcapng_pkts(entry, queue.index, packets, ret);

	return ret;
}

int odp_pktin_recv_tmo(odp_pktin_queue_t queue, odp_packet_t packets[], int num,
		       uint64_t wait)
{
	int ret;
	odp_time_t t1, t2;
	struct timespec ts;
	int started = 0;
	uint64_t sleep_round = 0;
	pktio_entry_t *entry;

	ts.tv_sec  = 0;
	ts.tv_nsec = 1000 * SLEEP_USEC;

	entry = get_pktio_entry(queue.pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", queue.pktio);
		return -1;
	}

	if (entry->s.ops->recv_tmo && wait != ODP_PKTIN_NO_WAIT) {
		ret = entry->s.ops->recv_tmo(entry, queue.index, packets, num,
					      wait);
		if (_ODP_PCAPNG)
			_odp_dump_pcapng_pkts(entry, queue.index, packets, ret);

		return ret;
	}

	while (1) {
		ret = entry->s.ops->recv(entry, queue.index, packets, num);
		if (_ODP_PCAPNG)
			_odp_dump_pcapng_pkts(entry, queue.index, packets, ret);

		if (ret != 0 || wait == 0)
			return ret;

		/* Avoid unnecessary system calls. Record the start time
		 * only when needed and after the first call to recv. */
		if (odp_unlikely(!started)) {
			odp_time_t t;

			/* Avoid overflow issues for large wait times */
			if (wait > MAX_WAIT_TIME)
				wait = MAX_WAIT_TIME;
			t = odp_time_local_from_ns(wait * 1000);
			started = 1;
			t1 = odp_time_sum(odp_time_local(), t);
		}

		/* Check every SLEEP_CHECK rounds if total wait time
		 * has been exceeded. */
		if ((++sleep_round & (SLEEP_CHECK - 1)) == 0) {
			t2 = odp_time_local();

			if (odp_time_cmp(t2, t1) > 0)
				return 0;
		}
		wait = wait > SLEEP_USEC ? wait - SLEEP_USEC : 0;

		nanosleep(&ts, NULL);
	}
}

int odp_pktin_recv_mq_tmo(const odp_pktin_queue_t queues[], unsigned num_q,
			  unsigned *from, odp_packet_t packets[], int num,
			  uint64_t wait)
{
	unsigned i;
	int ret;
	odp_time_t t1, t2;
	struct timespec ts;
	int started = 0;
	uint64_t sleep_round = 0;
	int trial_successful = 0;
	unsigned int lfrom = 0;

	for (i = 0; i < num_q; i++) {
		ret = odp_pktin_recv(queues[i], packets, num);

		if (ret > 0 && from)
			*from = i;

		if (ret != 0)
			return ret;
	}

	if (wait == 0)
		return 0;

	ret = sock_recv_mq_tmo_try_int_driven(queues, num_q, &lfrom,
					      packets, num, wait,
					      &trial_successful);
	if (ret > 0 && from)
		*from = lfrom;
	if (trial_successful) {
		if (_ODP_PCAPNG) {
			pktio_entry_t *entry;

			entry = get_pktio_entry(queues[lfrom].pktio);
			if (entry)
				_odp_dump_pcapng_pkts(entry, lfrom, packets,
						      ret);
		}

		return ret;
	}

	ts.tv_sec  = 0;
	ts.tv_nsec = 1000 * SLEEP_USEC;

	while (1) {
		for (i = 0; i < num_q; i++) {
			ret = odp_pktin_recv(queues[i], packets, num);

			if (ret > 0 && from)
				*from = i;

			if (ret != 0)
				return ret;
		}

		if (wait == 0)
			return 0;

		if (odp_unlikely(!started)) {
			odp_time_t t;

			/* Avoid overflow issues for large wait times */
			if (wait > MAX_WAIT_TIME)
				wait = MAX_WAIT_TIME;
			t = odp_time_local_from_ns(wait * 1000);
			started = 1;
			t1 = odp_time_sum(odp_time_local(), t);
		}

		/* Check every SLEEP_CHECK rounds if total wait time
		 * has been exceeded. */
		if ((++sleep_round & (SLEEP_CHECK - 1)) == 0) {
			t2 = odp_time_local();

			if (odp_time_cmp(t2, t1) > 0)
				return 0;
		}
		wait = wait > SLEEP_USEC ? wait - SLEEP_USEC : 0;

		nanosleep(&ts, NULL);
	}
}

uint64_t odp_pktin_wait_time(uint64_t nsec)
{
	if (nsec == 0)
		return 0;

	/* number of microseconds rounded up by one, so that
	 * recv_mq_tmo call waits at least 'nsec' nanoseconds. */
	return (nsec / (1000)) + 1;
}

int odp_pktout_send(odp_pktout_queue_t queue, const odp_packet_t packets[],
		    int num)
{
	pktio_entry_t *entry;
	odp_pktio_t pktio = queue.pktio;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", pktio);
		return -1;
	}

	if (_ODP_PCAPNG)
		_odp_dump_pcapng_pkts(entry, queue.index, packets, num);

	return entry->s.ops->send(entry, queue.index, packets, num);
}

/** Get printable format of odp_pktio_t */
uint64_t odp_pktio_to_u64(odp_pktio_t hdl)
{
	return _odp_pri(hdl);
}
