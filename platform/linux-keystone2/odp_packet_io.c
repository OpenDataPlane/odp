/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
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
#include <odp_sync.h>

#include <odp_pktio_socket.h>
#ifdef ODP_HAVE_NETMAP
#include <odp_pktio_netmap.h>
#endif

#include <string.h>

#define DUMMY_PKTIO

typedef struct {
	pktio_entry_t entries[ODP_CONFIG_PKTIO_ENTRIES];
} pktio_table_t;

static pktio_table_t *pktio_tbl;

#define MAX_PORT_INDEX 4
static int port_index(const char *interface)
{
	int ret, port;

	ret = sscanf(interface, "eth%d", &port);
	if (1 != ret)
		return -1;
	port++;
	if (port > MAX_PORT_INDEX)
		return -1;
	return port;
}

static pktio_entry_t *get_entry(odp_pktio_t id)
{
	if (odp_unlikely(id == ODP_PKTIO_INVALID ||
			 id > ODP_CONFIG_PKTIO_ENTRIES))
		return NULL;

	return &pktio_tbl->entries[id];
}

int odp_pktio_init_global(void)
{
	pktio_entry_t *pktio_entry;
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
	}
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

static int free_pktio_entry(odp_pktio_t id)
{
	pktio_entry_t *entry = get_entry(id);

	if (entry == NULL)
		return -1;

	set_free(entry);

	return 0;
}

static nwalTxPktInfo_t tx_pkt_info = {
		.pPkt = NULL,
		.txFlag1 = NWAL_TX_FLAG1_META_DATA_VALID,
		.lpbackPass = 0,
		.enetPort = 0,
		.mtuSize = 0,
		.startOffset = 0,
		.saOffBytes = 0,
		.saPayloadLen = 0,
		.saAhIcvOffBytes = 0,
		.saAhMacSize = 0,
		.etherLenOffBytes = 0,
		.ipOffBytes = 0,
		.l4OffBytes = 0,
		.l4HdrLen = 0,
		.pseudoHdrChecksum = 0,
		.ploadLen = 0,
};

odp_pktio_t odp_pktio_open(const char *dev, odp_buffer_pool_t pool,
			   odp_pktio_params_t *params ODP_UNUSED)
{
	odp_pktio_t id;
	pktio_entry_t *pktio_entry;
	char name[ODP_QUEUE_NAME_LEN];
	queue_entry_t *queue_entry;
	odp_queue_t qid = ODP_QUEUE_INVALID;
	nwal_RetValue ret_nwal;
	int port;

	odp_pr_dbg("Allocating HW pktio\n");

	/* Create a default output queue for each pktio resource */
	port = port_index(dev);
	if (port < 0) {
		odp_pr_err("Wrong pktio name: %s\n", dev);
		return ODP_PKTIO_INVALID;
	}

	/**
	 * Until classification API is in place there is no criteria to
	 * differentiate pktio except a port number. So map port directly
	 * to pktio entry.
	 */
	id = port;

	pktio_entry = get_entry(id);
	lock_entry(pktio_entry);
	if (!is_free(pktio_entry)) {
		/* Entry already initialized */
		odp_pr_dbg("PktIO %d is already initialized\n", id);
		goto unlock;
	}

	set_taken(pktio_entry);
	pktio_entry->s.inq_default = ODP_QUEUE_INVALID;
	pktio_entry->s.outq_default = ODP_QUEUE_INVALID;
	pktio_entry->s.port = port;

	snprintf(name, sizeof(name), "%i-pktio_outq_default", (int)id);
	name[ODP_QUEUE_NAME_LEN-1] = '\0';

	qid = odp_queue_create(name, ODP_QUEUE_TYPE_PKTOUT, NULL);
	odp_pr_dbg("Created queue %u\n", (uint32_t)qid);
	if (qid == ODP_QUEUE_INVALID) {
		free_pktio_entry(id);
		id = ODP_PKTIO_INVALID;
		odp_pr_err("Couldn't create queue: %s\n", name);
		goto unlock;
	}

	ret_nwal = nwal_initPSCmdInfo(odp_global->nwal.handle,
			&tx_pkt_info,
			&pktio_entry->s.tx_ps_cmdinfo);

	if (ret_nwal != nwal_OK) {
		odp_pr_err("Couldn't create PSCmdInfo\n");
		goto unlock;
	}

	pktio_entry->s.in_pool = pool;
	pktio_entry->s.outq_default = qid;
	pktio_entry->s.id = id;

	queue_entry = queue_to_qentry(qid);
	queue_entry->s.pktout_entry = pktio_entry;
unlock:
	unlock_entry(pktio_entry);
	return id;
}

int odp_pktio_close(odp_pktio_t id)
{
	pktio_entry_t *entry;

	entry = get_entry(id);
	if (entry == NULL)
		return -1;

	/* Only one entry per port exists, so no need to delete it */

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

static int pktio_inq_setdef_locked(odp_pktio_t id, odp_queue_t queue)
{
	nwal_RetValue nwal_ret;
	nwal_Handle handle;
	pktio_entry_t *pktio_entry = get_entry(id);
	queue_entry_t *queue_entry = queue_to_qentry(queue);
	nwalMacParam_t mac_info = {
			.validParams = NWAL_SET_MAC_VALID_PARAM_IFNUM,
			.ifNum = 0,
			.vlanId = 0,
			.macAddr =    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
			.remMacAddr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
			.matchAction = NWAL_MATCH_ACTION_HOST,
			.failAction = NWAL_NEXT_ROUTE_FAIL_ACTION_HOST,
			.appRxPktFlowId = CPPI_PARAM_NOT_SPECIFIED,
			.appRxPktQueue = QMSS_PARAM_NOT_SPECIFIED,
			.routeType = 0,
	};

	ODP_ASSERT(pktio_entry && queue_entry, "Not valid entries");
	ODP_ASSERT(queue_entry->s.type == ODP_QUEUE_TYPE_PKTIN,
		   "Not PKTIN queue");

	pktio_entry->s.inq_default = queue;
	odp_sync_stores();
	mac_info.appRxPktQueue = _odp_queue_to_qmss_queue(queue);
	/** @todo: Specify flow corresponding to the pool */
	mac_info.appRxPktFlowId = QMSS_PARAM_NOT_SPECIFIED;
	mac_info.ifNum = pktio_entry->s.port;

	nwal_ret = nwal_setMacIface(odp_global->nwal.handle,
			NWAL_TRANSID_SPIN_WAIT,
			(nwal_AppId) (0x12345678),
			&mac_info,
			&handle);
	if (nwal_ret != nwal_OK) {
		odp_pr_err("nwal_setMacIface returned Error Code %d\n",
			   nwal_ret);
		return -1;
	}

	odp_pr_info("MAC i/f added\n");

	queue_lock(queue_entry);
	queue_entry->s.pktin = id;
	queue_entry->s.status = QUEUE_STATUS_SCHED;
	queue_unlock(queue_entry);

	odp_schedule_queue(queue, queue_entry->s.param.sched.prio);

	return 0;
}

static int pktio_inq_create_setdef(odp_pktio_t id)
{
	char name[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t qparam;
	odp_queue_t inq_def;
	pktio_entry_t *pktio_entry = get_entry(id);
	int ret = 0;

	ODP_ASSERT(pktio_entry, "Not valid entry");
	lock_entry(pktio_entry);
	if (pktio_entry->s.inq_default != ODP_QUEUE_INVALID) {
		ret = 0;
		odp_pr_dbg("default input queue is already set: %u\n",
			   pktio_entry->s.inq_default);
		goto unlock;
	}

	odp_pr_dbg("Creating default input queue\n");
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_NONE;
	qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;
	snprintf(name, sizeof(name), "%i-pktio_inq_default", (int)id);
	name[ODP_QUEUE_NAME_LEN-1] = '\0';
	inq_def = odp_queue_create(name, ODP_QUEUE_TYPE_PKTIN, &qparam);
	if (inq_def == ODP_QUEUE_INVALID) {
		odp_pr_err("pktio input queue creation failed\n");
		ret = -1;
		goto unlock;
	}

	if (pktio_inq_setdef_locked(id, inq_def)) {
		odp_pr_err("default input-Q setup\n");
		ret = -1;
		goto unlock;
	}
unlock:
	unlock_entry(pktio_entry);
	return ret;
}

int odp_pktio_recv(odp_pktio_t id, odp_packet_t pkt_table[], unsigned len)
{
	pktio_entry_t *pktio_entry = get_entry(id);
	unsigned pkts = 0;
	odp_buffer_t buf;

	ODP_ASSERT(pktio_entry, "Not valid entry");

	if (pktio_entry->s.inq_default == ODP_QUEUE_INVALID) {
		/**
		 * Create a default input queue.
		 * @todo: It is a kind of WA for current ODP API usage.
		 * It should be revised.
		 */
		if (pktio_inq_create_setdef(id))
			return -1;
	}

	for (pkts = 0; pkts < len; pkts++) {
		buf = odp_queue_deq(pktio_entry->s.inq_default);
		if (!odp_buffer_is_valid(buf))
			break;

		pkt_table[pkts] = odp_packet_from_buffer(buf);
	}
	return pkts;
}

static inline void pktio_buffer_send(pktio_entry_t *pktio, odp_buffer_t buf)
{
	nwal_mCmdSetPort(_odp_buf_to_ti_pkt(buf),
			 &(pktio->s.tx_ps_cmdinfo),
			 pktio->s.port);

	Qmss_queuePushDescSize(pktio->s.tx_ps_cmdinfo.txQueue,
			       _odp_buf_to_cppi_desc(buf),
			       NWAL_DESC_SIZE);
}

int odp_pktio_send(odp_pktio_t id, odp_packet_t pkt_table[], unsigned len)
{
	pktio_entry_t *pktio_entry = get_entry(id);
	unsigned pkts;

	if (pktio_entry == NULL)
		return -1;

	for (pkts = 0; pkts < len; pkts++) {
		pktio_buffer_send(pktio_entry,
				  odp_buffer_from_packet(pkt_table[pkts]));
	}
	return pkts;
}

int odp_pktio_inq_setdef(odp_pktio_t id, odp_queue_t queue)
{
	pktio_entry_t *pktio_entry = get_entry(id);
	int ret = 0;

	ODP_ASSERT(pktio_entry, "Not valid entry");

	lock_entry(pktio_entry);
	if (pktio_entry->s.inq_default == ODP_QUEUE_INVALID) {
		ret = pktio_inq_setdef_locked(id, queue);
	} else {
		 /* Default queue can be assigned only once */
		odp_pr_err("pktio %u: default input queue %s is already set\n",
			   id,
			   odp_queue_name(pktio_entry->s.inq_default));
		ret = -1;
	}
	unlock_entry(pktio_entry);
	return ret;
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

int pktout_enqueue(queue_entry_t *queue, odp_buffer_t buf)
{
	pktio_entry_t *pktio = queue->s.pktout_entry;
	odp_pr_vdbg("sending packet\n");
	odp_pr_vdbg_packet(odp_packet_from_buffer(buf));
	pktio_buffer_send(pktio, buf);
	return 0;
}

int pktout_enq_multi(queue_entry_t *queue, odp_buffer_t buf[], int num)
{
	int i;
	pktio_entry_t *pktio = queue->s.pktout_entry;
	for (i = 0; i < num; i++)
		pktio_buffer_send(pktio, buf[i]);
	return 0;
}

static inline void update_in_packet(odp_buffer_t buf,
				    odp_pktio_t pktin)
{
	if (!odp_buffer_is_valid(buf))
		return;

	odp_packet_t pkt = odp_packet_from_buffer(buf);
	struct odp_pkthdr *pkt_hdr = odp_packet_hdr(pkt);
	size_t len = odp_packet_get_len(pkt);
	pkt_hdr->input = pktin;
	odp_packet_parse(pkt, len, 0);
}

odp_buffer_t pktin_dequeue(queue_entry_t *queue)
{
	odp_buffer_t buf;
	buf = queue_deq(queue);

	update_in_packet(buf, queue->s.pktin);
	return buf;
}

int pktin_deq_multi(queue_entry_t *queue, odp_buffer_t buf[], int num)
{
	int i;
	num = queue_deq_multi(queue, buf, num);

	for (i = 0; i < num; i++)
		update_in_packet(buf[i], queue->s.pktin);
	return num;
}
