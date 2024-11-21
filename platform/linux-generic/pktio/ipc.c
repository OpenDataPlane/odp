/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2019-2022 Nokia
 */

#include <odp/api/deprecated.h>
#include <odp/api/hints.h>
#include <odp/api/system_info.h>

#include <odp_debug_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_pool_internal.h>
#include <odp_macros_internal.h>
#include <odp_shm_internal.h>
#include <odp_ring_ptr_internal.h>
#include <odp_global_data.h>

#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Debug level for IPC */
#define IPC_DBG  3

/* Burst size for IPC free operations */
#define IPC_BURST_SIZE 32

/* that struct is exported to shared memory, so that processes can find
 * each other.
 */
struct pktio_info {
	struct {
		/* Pool base address */
		void *base_addr;
		/* number of buffer*/
		char pool_name[ODP_POOL_NAME_LEN];
		/* 1 if master finished creation of all shared objects */
		int init_done;
		/* IPC ring size */
		uint32_t ring_size;
		/* IPC ring mask */
		uint32_t ring_mask;
	} master;
	struct {
		/* Pool base address */
		void *base_addr;
		char pool_name[ODP_POOL_NAME_LEN];
		/* pid of the slave process written to shm and
		 * used by master to look up memory created by
		 * slave
		 */
		int pid;
		int init_done;
	} slave;
} ODP_PACKED;

typedef	struct {
	/* TX */
	struct  {
		/* ODP ring for IPC msg packets indexes transmitted to shared
		 * memory */
		ring_ptr_t	*send;
		/* ODP ring for IPC msg packets indexes already processed by
		 * remote process */
		ring_ptr_t	*free;
	} tx;
	/* RX */
	struct {
		/* ODP ring for IPC msg packets indexes received from shared
		 * memory (from remote process) */
		ring_ptr_t	*recv;
		/* odp ring for ipc msg packets indexes already processed by
		 * current process */
		ring_ptr_t	*free;
		/* local cache to keep packet order right */
		ring_ptr_t	*cache;
	} rx; /* slave */
	/* Remote pool mdata base addr */
	void *pool_mdata_base;
	/* Remote pool base address for offset calculation */
	void *remote_base_addr;
	odp_pool_t	pool;		/**< Pool of main process */
	enum {
		PKTIO_TYPE_IPC_MASTER = 0, /**< Master is the process which
						creates shm */
		PKTIO_TYPE_IPC_SLAVE	   /**< Slave is the process which
						connects to shm */
	} type; /**< define if it's master or slave process */
	odp_atomic_u32_t ready; /**< 1 - pktio is ready and can recv/send
				     packet, 0 - not yet ready */
	/* Local copy of IPC ring size */
	uint32_t ring_size;
	/* Local copy IPC ring mask */
	uint32_t ring_mask;
	struct pktio_info *pinfo;
	odp_shm_t pinfo_shm;
	odp_shm_t remote_pool_shm; /**< shm of remote pool get with
					_ipc_map_remote_pool() */
} pkt_ipc_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_ipc_t),
		  "PKTIO_PRIVATE_SIZE too small");

static inline pkt_ipc_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_ipc_t *)(uintptr_t)(pktio_entry->pkt_priv);
}

/* MAC address for the "ipc" interface */
static const uint8_t pktio_ipc_mac[] = {0x12, 0x12, 0x12, 0x12, 0x12, 0x12};

static odp_shm_t _ipc_map_remote_pool(const char *name, int pid);

/* create the ring */
static ring_ptr_t *_ring_create(const char *name, uint32_t count,
				uint32_t shm_flags)
{
	ring_ptr_t *r;
	size_t ring_size;
	odp_shm_t shm;

	if (odp_global_ro.shm_single_va)
		shm_flags |= ODP_SHM_SINGLE_VA;

	/* count must be a power of 2 */
	if (!_ODP_CHECK_IS_POWER2(count)) {
		_ODP_ERR("Requested size is invalid, must be a power of 2\n");
		return NULL;
	}

	ring_size = sizeof(ring_ptr_t) + count * sizeof(void *);

	/* reserve a memory zone for this ring.*/
	shm = odp_shm_reserve(name, ring_size, ODP_CACHE_LINE_SIZE, shm_flags);

	r = odp_shm_addr(shm);
	if (r != NULL) {
		/* init the ring structure */
		ring_ptr_init(r);

	} else {
		_ODP_ERR("Cannot reserve memory\n");
	}

	return r;
}

static int _ring_destroy(const char *name)
{
	odp_shm_t shm = odp_shm_lookup(name);

	if (shm != ODP_SHM_INVALID)
		return odp_shm_free(shm);

	return 0;
}

/**
 * Return the number of entries in a ring.
 */
static uint32_t _ring_count(ring_ptr_t *r, uint32_t mask)
{
	uint32_t prod_tail = odp_atomic_load_u32(&r->r.w_tail);
	uint32_t cons_tail = odp_atomic_load_u32(&r->r.r_tail);

	return (prod_tail - cons_tail) & mask;
}

/**
 * Return the number of free entries in a ring.
 */
static uint32_t _ring_free_count(ring_ptr_t *r, uint32_t mask)
{
	uint32_t prod_tail = odp_atomic_load_u32(&r->r.w_tail);
	uint32_t cons_tail = odp_atomic_load_u32(&r->r.r_tail);

	return (cons_tail - prod_tail - 1) & mask;
}

static const char *_ipc_odp_buffer_pool_shm_name(odp_pool_t pool_hdl)
{
	pool_t *pool;
	odp_shm_t shm;
	odp_shm_info_t info;

	pool = _odp_pool_entry(pool_hdl);
	shm = pool->shm;

	if (odp_shm_info(shm, &info))
		return "name_unknown";

	return info.name;
}

static int _ipc_master_start(pktio_entry_t *pktio_entry)
{
	pkt_ipc_t *pktio_ipc = pkt_priv(pktio_entry);
	struct pktio_info *pinfo = pktio_ipc->pinfo;
	odp_shm_t shm;

	if (pinfo->slave.init_done == 0)
		return -1;

	shm = _ipc_map_remote_pool(pinfo->slave.pool_name,
				   pinfo->slave.pid);
	if (shm == ODP_SHM_INVALID) {
		_ODP_DBG("no pool file %s for pid %d\n", pinfo->slave.pool_name, pinfo->slave.pid);
		return -1;
	}

	pktio_ipc->remote_pool_shm = shm;
	pktio_ipc->remote_base_addr = pinfo->slave.base_addr;
	pktio_ipc->pool_mdata_base = (char *)odp_shm_addr(shm);

	odp_atomic_store_u32(&pktio_ipc->ready, 1);

	ODP_DBG_LVL(IPC_DBG, "%s started.\n",  pktio_entry->name);
	return 0;
}

static int _ipc_init_master(pktio_entry_t *pktio_entry,
			    const char *dev,
			    odp_pool_t pool_hdl)
{
	pkt_ipc_t *pktio_ipc = pkt_priv(pktio_entry);
	char ipc_shm_name[ODP_POOL_NAME_LEN + sizeof("_m_prod")];
	struct pktio_info *pinfo;
	const char *pool_name;
	pool_t *pool = _odp_pool_entry(pool_hdl);
	uint32_t ring_size;
	uint32_t ring_mask;

	if ((uint64_t)_ODP_ROUNDUP_POWER2_U32(pool->num + 1) > UINT32_MAX) {
		_ODP_ERR("Too large packet pool\n");
		return -1;
	}

	/* Ring must be able to store all packets in the pool */
	ring_size = _ODP_ROUNDUP_POWER2_U32(pool->num + 1);

	/* Ring size has to larger than burst size */
	if (ring_size <= IPC_BURST_SIZE)
		ring_size = _ODP_ROUNDUP_POWER2_U32(IPC_BURST_SIZE + 1);
	ring_mask = ring_size - 1;

	pktio_ipc->ring_size = ring_size;
	pktio_ipc->ring_mask = ring_mask;

	if (strlen(dev) > (ODP_POOL_NAME_LEN - sizeof("_m_prod"))) {
		_ODP_ERR("too big ipc name\n");
		return -1;
	}

	pktio_ipc->rx.cache = _ring_create("ipc_rx_cache", ring_size, 0);
	if (!pktio_ipc->rx.cache) {
		_ODP_ERR("pid %d unable to create ipc rx cache\n", getpid());
		return -1;
	}

	/* generate name in shm like ipc_pktio_r for
	 * to be processed packets ring.
	 */
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_prod", dev);
	pktio_ipc->tx.send = _ring_create(ipc_shm_name, ring_size,
					  ODP_SHM_PROC | ODP_SHM_EXPORT);
	if (!pktio_ipc->tx.send) {
		_ODP_ERR("pid %d unable to create ipc ring %s name\n", getpid(), ipc_shm_name);
		return -1;
	}
	_ODP_DBG("Created IPC ring: %s, count %d, free %d\n",
		 ipc_shm_name, _ring_count(pktio_ipc->tx.send, ring_mask),
		 _ring_free_count(pktio_ipc->tx.send, ring_mask));

	/* generate name in shm like ipc_pktio_p for
	 * already processed packets
	 */
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_cons", dev);
	pktio_ipc->tx.free = _ring_create(ipc_shm_name, ring_size,
					  ODP_SHM_PROC | ODP_SHM_EXPORT);
	if (!pktio_ipc->tx.free) {
		_ODP_ERR("pid %d unable to create ipc ring %s name\n", getpid(), ipc_shm_name);
		goto free_m_prod;
	}
	_ODP_DBG("Created IPC ring: %s, count %d, free %d\n",
		 ipc_shm_name, _ring_count(pktio_ipc->tx.free, ring_mask),
		 _ring_free_count(pktio_ipc->tx.free, ring_mask));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_prod", dev);
	pktio_ipc->rx.recv = _ring_create(ipc_shm_name, ring_size,
					  ODP_SHM_PROC | ODP_SHM_EXPORT);
	if (!pktio_ipc->rx.recv) {
		_ODP_ERR("pid %d unable to create ipc ring %s name\n", getpid(), ipc_shm_name);
		goto free_m_cons;
	}
	_ODP_DBG("Created IPC ring: %s, count %d, free %d\n",
		 ipc_shm_name, _ring_count(pktio_ipc->rx.recv, ring_mask),
		 _ring_free_count(pktio_ipc->rx.recv, ring_mask));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_cons", dev);
	pktio_ipc->rx.free = _ring_create(ipc_shm_name, ring_size,
					  ODP_SHM_PROC | ODP_SHM_EXPORT);
	if (!pktio_ipc->rx.free) {
		_ODP_ERR("pid %d unable to create ipc ring %s name\n", getpid(), ipc_shm_name);
		goto free_s_prod;
	}
	_ODP_DBG("Created IPC ring: %s, count %d, free %d\n",
		 ipc_shm_name, _ring_count(pktio_ipc->rx.free, ring_mask),
		 _ring_free_count(pktio_ipc->rx.free, ring_mask));

	/* Set up pool name for remote info */
	pinfo = pktio_ipc->pinfo;
	pool_name = _ipc_odp_buffer_pool_shm_name(pool_hdl);
	if (strlen(pool_name) >= ODP_POOL_NAME_LEN) {
		_ODP_ERR("pid %d ipc pool name %s is too big %zu\n",
			 getpid(), pool_name, strlen(pool_name));
		goto free_s_prod;
	}

	strcpy(pinfo->master.pool_name, pool_name);

	/* Export ring info for the slave process to use */
	pinfo->master.ring_size = ring_size;
	pinfo->master.ring_mask = ring_mask;
	pinfo->master.base_addr = odp_shm_addr(pool->shm);

	pinfo->slave.base_addr = 0;
	pinfo->slave.pid = 0;
	pinfo->slave.init_done = 0;

	pktio_ipc->pool = pool_hdl;

	_ODP_DBG("Pre init... DONE.\n");
	pinfo->master.init_done = 1;

	_ipc_master_start(pktio_entry);

	return 0;

free_s_prod:
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_prod", dev);
	_ring_destroy(ipc_shm_name);
free_m_cons:
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_cons", dev);
	_ring_destroy(ipc_shm_name);
free_m_prod:
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_prod", dev);
	_ring_destroy(ipc_shm_name);
	return -1;
}

static void _ipc_export_pool(struct pktio_info *pinfo,
			     odp_pool_t pool_hdl)
{
	pool_t *pool = _odp_pool_entry(pool_hdl);

	snprintf(pinfo->slave.pool_name, ODP_POOL_NAME_LEN, "%s",
		 _ipc_odp_buffer_pool_shm_name(pool_hdl));
	pinfo->slave.pid = odp_global_ro.main_pid;
	pinfo->slave.base_addr = odp_shm_addr(pool->shm);
}

static odp_shm_t _ipc_map_remote_pool(const char *name, int pid)
{
	odp_shm_t shm;
	char rname[ODP_SHM_NAME_LEN];

	snprintf(rname, ODP_SHM_NAME_LEN, "remote-%s", name);
	shm = odp_shm_import(name, pid, rname);
	if (shm == ODP_SHM_INVALID) {
		_ODP_ERR("unable map %s\n", name);
		return ODP_SHM_INVALID;
	}

	ODP_DBG_LVL(IPC_DBG, "Mapped remote pool %s to local %s\n", name, rname);
	return shm;
}

static void *_ipc_shm_map(char *name, int pid)
{
	odp_shm_t shm;

	shm = odp_shm_import(name, pid, name);
	if (ODP_SHM_INVALID == shm) {
		_ODP_ERR("unable to map: %s\n", name);
		return NULL;
	}

	return odp_shm_addr(shm);
}

static int _ipc_init_slave(const char *dev, pktio_entry_t *pktio_entry,
			   odp_pool_t pool_hdl)
{
	pkt_ipc_t *pktio_ipc = pkt_priv(pktio_entry);
	pool_t *pool = _odp_pool_entry(pool_hdl);
	uint32_t ring_size = pktio_ipc->pinfo->master.ring_size;

	if (strlen(dev) > (ODP_POOL_NAME_LEN - sizeof("_slave_r"))) {
		_ODP_ERR("Too big ipc name\n");
		return -1;
	}

	/* Check that IPC rings are able to store all packets */
	if (pool->num >= ring_size) {
		_ODP_ERR("Slave process packet pool too large. Master process "
			"packet pool has to be larger than slave pool.\n");
		return -1;
	}

	pktio_ipc->rx.cache = _ring_create("ipc_rx_cache", ring_size, 0);
	if (!pktio_ipc->rx.cache) {
		_ODP_ERR("Pid %d unable to create ipc rx cache\n", getpid());
		return -1;
	}
	pktio_ipc->ring_size = ring_size;
	pktio_ipc->ring_mask = pktio_ipc->pinfo->master.ring_mask;
	pktio_ipc->pool = pool_hdl;

	return 0;
}

static int _ipc_slave_start(pktio_entry_t *pktio_entry)
{
	pkt_ipc_t *pktio_ipc = pkt_priv(pktio_entry);
	char ipc_shm_name[ODP_POOL_NAME_LEN + sizeof("_slave_r")];
	struct pktio_info *pinfo;
	odp_shm_t shm;
	char tail[ODP_POOL_NAME_LEN];
	char dev[ODP_POOL_NAME_LEN];
	int pid;
	uint32_t ring_mask = pktio_ipc->ring_mask;

	if (sscanf(pktio_entry->name, "ipc:%d:%s", &pid, tail) != 2) {
		_ODP_ERR("wrong pktio name\n");
		return -1;
	}

	sprintf(dev, "ipc:%s", tail);

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_prod", dev);
	pktio_ipc->rx.recv  = _ipc_shm_map(ipc_shm_name, pid);
	if (!pktio_ipc->rx.recv) {
		_ODP_DBG("pid %d unable to find ipc ring %s name\n", getpid(), dev);
		sleep(1);
		return -1;
	}
	_ODP_DBG("Connected IPC ring: %s, count %d, free %d\n",
		 ipc_shm_name, _ring_count(pktio_ipc->rx.recv, ring_mask),
		 _ring_free_count(pktio_ipc->rx.recv, ring_mask));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_cons", dev);
	pktio_ipc->rx.free = _ipc_shm_map(ipc_shm_name, pid);
	if (!pktio_ipc->rx.free) {
		_ODP_ERR("pid %d unable to find ipc ring %s name\n", getpid(), dev);
		goto free_m_prod;
	}
	_ODP_DBG("Connected IPC ring: %s, count %d, free %d\n",
		 ipc_shm_name, _ring_count(pktio_ipc->rx.free, ring_mask),
		 _ring_free_count(pktio_ipc->rx.free, ring_mask));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_prod", dev);
	pktio_ipc->tx.send = _ipc_shm_map(ipc_shm_name, pid);
	if (!pktio_ipc->tx.send) {
		_ODP_ERR("pid %d unable to find ipc ring %s name\n", getpid(), dev);
		goto free_m_cons;
	}
	_ODP_DBG("Connected IPC ring: %s, count %d, free %d\n",
		 ipc_shm_name, _ring_count(pktio_ipc->tx.send, ring_mask),
		 _ring_free_count(pktio_ipc->tx.send, ring_mask));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_cons", dev);
	pktio_ipc->tx.free = _ipc_shm_map(ipc_shm_name, pid);
	if (!pktio_ipc->tx.free) {
		_ODP_ERR("pid %d unable to find ipc ring %s name\n", getpid(), dev);
		goto free_s_prod;
	}
	_ODP_DBG("Connected IPC ring: %s, count %d, free %d\n",
		 ipc_shm_name, _ring_count(pktio_ipc->tx.free, ring_mask),
		 _ring_free_count(pktio_ipc->tx.free, ring_mask));

	/* Get info about remote pool */
	pinfo = pktio_ipc->pinfo;
	shm = _ipc_map_remote_pool(pinfo->master.pool_name,
				   pid);
	pktio_ipc->remote_pool_shm = shm;
	pktio_ipc->pool_mdata_base = (char *)odp_shm_addr(shm);
	pktio_ipc->remote_base_addr = pinfo->master.base_addr;

	_ipc_export_pool(pinfo, pktio_ipc->pool);

	odp_atomic_store_u32(&pktio_ipc->ready, 1);
	pinfo->slave.init_done = 1;

	_ODP_DBG("%s started.\n",  pktio_entry->name);
	return 0;

free_s_prod:
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_prod", dev);
	shm = odp_shm_lookup(ipc_shm_name);
	odp_shm_free(shm);
free_m_cons:
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_cons", dev);
	shm = odp_shm_lookup(ipc_shm_name);
	odp_shm_free(shm);
free_m_prod:
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_prod", dev);
	shm = odp_shm_lookup(ipc_shm_name);
	odp_shm_free(shm);
	return -1;
}

static int ipc_pktio_open(odp_pktio_t id ODP_UNUSED,
			  pktio_entry_t *pktio_entry,
			  const char *dev,
			  odp_pool_t pool)
{
	pkt_ipc_t *pktio_ipc = pkt_priv(pktio_entry);
	int ret = 0;
	int pid;
	struct pktio_info *pinfo;
	char name[ODP_POOL_NAME_LEN + sizeof("_info")];
	char tail[ODP_POOL_NAME_LEN];
	odp_shm_t shm;

	if (strncmp(dev, "ipc", 3))
		return -1;

	odp_atomic_init_u32(&pktio_ipc->ready, 0);

	/* Shared info about remote pktio */
	if (sscanf(dev, "ipc:%d:%s", &pid, tail) == 2) {
		pktio_ipc->type = PKTIO_TYPE_IPC_SLAVE;

		snprintf(name, sizeof(name), "ipc:%s_info", tail);
		ODP_DBG_LVL(IPC_DBG, "lookup for name %s for pid %d\n", name, pid);
		shm = odp_shm_import(name, pid, name);
		if (ODP_SHM_INVALID == shm)
			return -1;

		pinfo = odp_shm_addr(shm);

		if (!pinfo->master.init_done) {
			odp_shm_free(shm);
			return -1;
		}
		pktio_ipc->pinfo = pinfo;
		pktio_ipc->pinfo_shm = shm;
		_ODP_DBG("process %d is slave\n", getpid());
		ret = _ipc_init_slave(name, pktio_entry, pool);
	} else {
		pktio_ipc->type = PKTIO_TYPE_IPC_MASTER;
		snprintf(name, sizeof(name), "%s_info", dev);
		shm = odp_shm_reserve(name, sizeof(struct pktio_info),
				      ODP_CACHE_LINE_SIZE,
				      ODP_SHM_EXPORT | ODP_SHM_SINGLE_VA);
		if (ODP_SHM_INVALID == shm) {
			_ODP_ERR("can not create shm %s\n", name);
			return -1;
		}

		pinfo = odp_shm_addr(shm);
		pinfo->master.init_done = 0;
		pinfo->master.pool_name[0] = 0;

		pktio_ipc->pinfo = pinfo;
		pktio_ipc->pinfo_shm = shm;
		_ODP_DBG("process %d is master\n", getpid());
		ret = _ipc_init_master(pktio_entry, dev, pool);
	}

	if (ret)
		odp_shm_free(shm);

	return ret;
}

static void _ipc_free_ring_packets(pktio_entry_t *pktio_entry, ring_ptr_t *r,
				   uint32_t r_mask)
{
	pkt_ipc_t *pktio_ipc = pkt_priv(pktio_entry);
	uintptr_t offsets[IPC_BURST_SIZE];
	int ret;
	void **rbuf_p;
	int i;
	void *addr;
	pool_t *pool;

	if (!r)
		return;

	pool = _odp_pool_entry(pktio_ipc->pool);
	addr = odp_shm_addr(pool->shm);

	rbuf_p = (void *)&offsets;

	while (1) {
		ret = ring_ptr_deq_multi(r, r_mask, rbuf_p, IPC_BURST_SIZE);
		if (ret <= 0)
			break;
		for (i = 0; i < ret; i++) {
			odp_packet_hdr_t *phdr;
			odp_packet_t pkt;

			phdr = (void *)((uint8_t *)addr + offsets[i]);
			pkt = packet_handle(phdr);

			odp_packet_free(pkt);
		}
	}
}

static int ipc_pktio_recv_lockless(pktio_entry_t *pktio_entry,
				   odp_packet_t pkt_table[], int len)
{
	pkt_ipc_t *pktio_ipc = pkt_priv(pktio_entry);
	uint32_t ring_mask = pktio_ipc->ring_mask;
	int pkts = 0;
	int i;
	ring_ptr_t *r;
	ring_ptr_t *r_p;
	uintptr_t offsets[len];
	void **ipcbufs_p = (void *)&offsets[0];
	uint32_t ready;

	ready = odp_atomic_load_u32(&pktio_ipc->ready);
	if (odp_unlikely(!ready)) {
		ODP_DBG_LVL(IPC_DBG, "start pktio is missing before usage?\n");
		return 0;
	}

	_ipc_free_ring_packets(pktio_entry, pktio_ipc->tx.free, ring_mask);

	/* rx from cache */
	r = pktio_ipc->rx.cache;
	pkts = ring_ptr_deq_multi(r, ring_mask, ipcbufs_p, len);
	if (odp_unlikely(pkts < 0))
		_ODP_ABORT("internal error dequeue\n");

	/* rx from other app */
	if (pkts == 0) {
		ipcbufs_p = (void *)&offsets[0];
		r = pktio_ipc->rx.recv;
		pkts = ring_ptr_deq_multi(r, ring_mask, ipcbufs_p,
					  len);
		if (odp_unlikely(pkts < 0))
			_ODP_ABORT("internal error dequeue\n");
	}

	/* fast path */
	if (odp_likely(0 == pkts))
		return 0;

	for (i = 0; i < pkts; i++) {
		odp_pool_t pool;
		odp_packet_t pkt;
		odp_packet_hdr_t *phdr;
		void *pkt_data;
		uint64_t data_pool_off;
		void *rmt_data_ptr;

		phdr = (void *)((uint8_t *)pktio_ipc->pool_mdata_base +
				offsets[i]);

		pool = pktio_ipc->pool;
		if (odp_unlikely(pool == ODP_POOL_INVALID))
			_ODP_ABORT("invalid pool");

		data_pool_off = (uint8_t *)phdr->seg_data -
				(uint8_t *)pktio_ipc->remote_base_addr;

		pkt = odp_packet_alloc(pool, phdr->frame_len);
		if (odp_unlikely(pkt == ODP_PACKET_INVALID)) {
			/* Original pool might be smaller then
			*  ring size. If packet can not be
			 * allocated from pool at this time,
			 * simple get in on next recv() call. To keep
			 * packet ordering store such packets in local
			 * cache.
			 */
			ODP_DBG_LVL(IPC_DBG, "unable to allocate packet %d/%d\n",
				    i, pkts);
			break;
		}

		/* Copy packet data. */
		pkt_data = odp_packet_data(pkt);
		if (odp_unlikely(!pkt_data))
			_ODP_ABORT("unable to map pkt_data ipc_slave %d\n",
				   (PKTIO_TYPE_IPC_SLAVE == pktio_ipc->type));

		/* Copy packet data from shared pool to local pool. */
		rmt_data_ptr = (uint8_t *)pktio_ipc->pool_mdata_base +
				data_pool_off;
		memcpy(pkt_data, rmt_data_ptr, phdr->frame_len);

		/* Copy packets L2, L3 parsed offsets and size */
		_odp_packet_copy_cls_md(packet_hdr(pkt), phdr);

		packet_hdr(pkt)->frame_len = phdr->frame_len;
		packet_hdr(pkt)->headroom = phdr->headroom;
		packet_hdr(pkt)->tailroom = phdr->tailroom;

		/* Take classification fields */
		packet_hdr(pkt)->p = phdr->p;

		pkt_table[i] = pkt;
	}

	/* put back to rx ring dequeued but not processed packets*/
	if (pkts != i) {
		ipcbufs_p = (void *)&offsets[i];
		r_p = pktio_ipc->rx.cache;
		ring_ptr_enq_multi(r_p, ring_mask, ipcbufs_p,
				   pkts - i);

		if (i == 0)
			return 0;
	}

	/*num of actually received packets*/
	pkts = i;

	/* Now tell other process that we no longer need that buffers.*/
	r_p = pktio_ipc->rx.free;

	ipcbufs_p = (void *)&offsets[0];
	ring_ptr_enq_multi(r_p, ring_mask, ipcbufs_p, pkts);

	for (i = 0; i < pkts; i++) {
		ODP_DBG_LVL(IPC_DBG, "%d/%d send to be free packet offset %" PRIuPTR "\n",
			    i, pkts, offsets[i]);
	}

	return pkts;
}

static int ipc_pktio_recv(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			  odp_packet_t pkt_table[], int num)
{
	int ret;

	odp_ticketlock_lock(&pktio_entry->rxl);

	ret = ipc_pktio_recv_lockless(pktio_entry, pkt_table, num);

	odp_ticketlock_unlock(&pktio_entry->rxl);

	return ret;
}

static int ipc_pktio_send_lockless(pktio_entry_t *pktio_entry,
				   const odp_packet_t pkt_table[], int num)
{
	pkt_ipc_t *pktio_ipc = pkt_priv(pktio_entry);
	uint32_t ring_mask = pktio_ipc->ring_mask;
	ring_ptr_t *r;
	void **rbuf_p;
	int i;
	uint32_t ready = odp_atomic_load_u32(&pktio_ipc->ready);
	pool_t *ipc_pool = _odp_pool_entry(pktio_ipc->pool);
	odp_packet_t pkt_table_mapped[num]; /**< Ready to send packet has to be
					      * in memory mapped pool. */
	uintptr_t offsets[num];

	if (odp_unlikely(!ready))
		return 0;

	_ipc_free_ring_packets(pktio_entry, pktio_ipc->tx.free, ring_mask);

	/* Copy packets to shm shared pool if they are in different
	 * pool, or if they are references (we can't share across IPC).
	 */
	for (i = 0; i < num; i++) {
		odp_packet_t pkt =  pkt_table[i];
		odp_packet_hdr_t *pkt_hdr;
		pool_t *pool;

		pkt_hdr = packet_hdr(pkt);
		pool = _odp_pool_entry(pkt_hdr->event_hdr.pool);

		if (pool->pool_idx != ipc_pool->pool_idx ||
		    odp_packet_has_ref(pkt)) {
			odp_packet_t newpkt;

			newpkt = odp_packet_copy(pkt, pktio_ipc->pool);
			if (newpkt == ODP_PACKET_INVALID)
				_ODP_ABORT("Unable to copy packet\n");

			odp_packet_free(pkt);
			pkt_table_mapped[i] = newpkt;
		} else {
			pkt_table_mapped[i] = pkt;
		}
	}

	/* Set offset to phdr for outgoing packets */
	for (i = 0; i < num; i++) {
		odp_packet_t pkt = pkt_table_mapped[i];
		odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
		odp_pool_t pool_hdl = odp_packet_pool(pkt);
		pool_t *pool = _odp_pool_entry(pool_hdl);

		offsets[i] = (uint8_t *)pkt_hdr -
			     (uint8_t *)odp_shm_addr(pool->shm);

		/* compile all function code even if ipc disabled with config */
		ODP_DBG_LVL(IPC_DBG, "%d/%d send packet %" PRIu64 ", pool %" PRIu64 ","
			    "phdr = %p, offset %td, sendoff %" PRIxPTR ", addr %p iaddr "
			    "%p\n", i, num,
			    odp_packet_to_u64(pkt), odp_pool_to_u64(pool_hdl),
			    (void *)pkt_hdr, (uint8_t *)pkt_hdr->seg_data -
			    (uint8_t *)odp_shm_addr(pool->shm), offsets[i],
			    odp_shm_addr(pool->shm),
			    odp_shm_addr(ipc_pool->shm));
	}

	/* Put packets to ring to be processed by other process. */
	rbuf_p = (void *)&offsets[0];
	r = pktio_ipc->tx.send;
	ring_ptr_enq_multi(r, ring_mask, rbuf_p, num);

	return num;
}

static int ipc_pktio_send(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			  const odp_packet_t pkt_table[], int num)
{
	int ret;

	odp_ticketlock_lock(&pktio_entry->txl);

	ret = ipc_pktio_send_lockless(pktio_entry, pkt_table, num);

	odp_ticketlock_unlock(&pktio_entry->txl);

	return ret;
}

static uint32_t ipc_mtu_get(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	/* mtu not limited, pool settings are used. */
	return (9 * 1024);
}

static int ipc_mac_addr_get(pktio_entry_t *pktio_entry ODP_UNUSED,
			    void *mac_addr)
{
	memcpy(mac_addr, pktio_ipc_mac, ETH_ALEN);
	return ETH_ALEN;
}

static int ipc_start(pktio_entry_t *pktio_entry)
{
	pkt_ipc_t *pktio_ipc = pkt_priv(pktio_entry);
	uint32_t ready = odp_atomic_load_u32(&pktio_ipc->ready);

	if (ready) {
		_ODP_ABORT("%s Already started\n", pktio_entry->name);
		return -1;
	}

	if (pktio_ipc->type == PKTIO_TYPE_IPC_MASTER)
		return _ipc_master_start(pktio_entry);
	else
		return _ipc_slave_start(pktio_entry);
}

static int ipc_stop(pktio_entry_t *pktio_entry)
{
	pkt_ipc_t *pktio_ipc = pkt_priv(pktio_entry);
	uint32_t ring_mask = pktio_ipc->ring_mask;

	odp_atomic_store_u32(&pktio_ipc->ready, 0);

	if (pktio_ipc->tx.send)
		_ipc_free_ring_packets(pktio_entry, pktio_ipc->tx.send,
				       ring_mask);
	/* other process can transfer packets from one ring to
	 * other, use delay here to free that packets. */
	sleep(1);
	if (pktio_ipc->tx.free)
		_ipc_free_ring_packets(pktio_entry, pktio_ipc->tx.free,
				       ring_mask);

	return 0;
}

static int ipc_link_status(pktio_entry_t *pktio_entry)
{
	pkt_ipc_t *pktio_ipc = pkt_priv(pktio_entry);

	if (odp_atomic_load_u32(&pktio_ipc->ready))
		return ODP_PKTIO_LINK_STATUS_UP;
	return ODP_PKTIO_LINK_STATUS_DOWN;
}

static int ipc_link_info(pktio_entry_t *pktio_entry, odp_pktio_link_info_t *info)
{
	pkt_ipc_t *pktio_ipc = pkt_priv(pktio_entry);

	memset(info, 0, sizeof(odp_pktio_link_info_t));

	info->autoneg = ODP_PKTIO_LINK_AUTONEG_OFF;
	info->duplex = ODP_PKTIO_LINK_DUPLEX_FULL;
	info->media = "virtual";
	info->pause_rx = ODP_PKTIO_LINK_PAUSE_OFF;
	info->pause_tx = ODP_PKTIO_LINK_PAUSE_OFF;
	info->speed = ODP_PKTIO_LINK_SPEED_UNKNOWN;
	if (odp_atomic_load_u32(&pktio_ipc->ready))
		info->status = ODP_PKTIO_LINK_STATUS_UP;
	else
		info->status = ODP_PKTIO_LINK_STATUS_DOWN;

	return 0;
}

static int ipc_capability(pktio_entry_t *pktio_entry ODP_UNUSED, odp_pktio_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues  = 1;
	capa->max_output_queues = 1;
	capa->config.pktout.bit.tx_compl_ena = 1;
#if ODP_DEPRECATED_API
	capa->tx_compl.mode_all = 1;
#endif
	capa->tx_compl.mode_event = 1;
	capa->tx_compl.mode_poll = 1;

	return 0;
}

static int ipc_close(pktio_entry_t *pktio_entry)
{
	pkt_ipc_t *pktio_ipc = pkt_priv(pktio_entry);
	char ipc_shm_name[ODP_POOL_NAME_LEN + sizeof("_m_prod")];
	char *dev = pktio_entry->name;
	char name[ODP_POOL_NAME_LEN];
	char tail[ODP_POOL_NAME_LEN];
	int pid = 0;

	ipc_stop(pktio_entry);

	odp_shm_free(pktio_ipc->remote_pool_shm);

	if (sscanf(dev, "ipc:%d:%s", &pid, tail) == 2)
		snprintf(name, sizeof(name), "ipc:%s", tail);
	else
		snprintf(name, sizeof(name), "%s", dev);

	/* unlink this pktio info for both master and slave */
	odp_shm_free(pktio_ipc->pinfo_shm);

	/* destroy rings */
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_cons", name);
	_ring_destroy(ipc_shm_name);
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_prod", name);
	_ring_destroy(ipc_shm_name);
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_cons", name);
	_ring_destroy(ipc_shm_name);
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_prod", name);
	_ring_destroy(ipc_shm_name);
	_ring_destroy("ipc_rx_cache");

	return 0;
}

const pktio_if_ops_t _odp_ipc_pktio_ops = {
	.name = "ipc",
	.print = NULL,
	.init_global = NULL,
	.init_local = NULL,
	.term = NULL,
	.open = ipc_pktio_open,
	.close = ipc_close,
	.recv =  ipc_pktio_recv,
	.send = ipc_pktio_send,
	.start = ipc_start,
	.stop = ipc_stop,
	.link_status = ipc_link_status,
	.link_info = ipc_link_info,
	.capability = ipc_capability,
	.maxlen_get = ipc_mtu_get,
	.promisc_mode_set = NULL,
	.promisc_mode_get = NULL,
	.mac_get = ipc_mac_addr_get,
	.mac_set = NULL,
	.pktio_ts_res = NULL,
	.pktio_ts_from_ns = NULL,
	.pktio_time = NULL,
	.config = NULL
};
