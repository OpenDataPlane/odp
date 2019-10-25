/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_debug_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_errno_define.h>
#include <odp/api/system_info.h>
#include <odp_shm_internal.h>
#include <odp_ring_ptr_internal.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define IPC_ODP_DEBUG_PRINT 0

#define IPC_ODP_DBG(fmt, ...) \
	do { \
		if (IPC_ODP_DEBUG_PRINT == 1) \
			ODP_DBG(fmt, ##__VA_ARGS__);\
	} while (0)

/* number of odp buffers in odp ring queue */
#define PKTIO_IPC_ENTRIES 4096

#define PKTIO_IPC_ENTRY_MASK (PKTIO_IPC_ENTRIES - 1)

/* that struct is exported to shared memory, so that processes can find
 * each other.
 */
struct pktio_info {
	struct {
		/* number of buffer*/
		int num;
		/* size of packet/segment in remote pool */
		uint32_t block_size;
		char pool_name[ODP_POOL_NAME_LEN];
		/* 1 if master finished creation of all shared objects */
		int init_done;
	} master;
	struct {
		void *base_addr;
		uint32_t block_size;
		char pool_name[ODP_POOL_NAME_LEN];
		/* pid of the slave process written to shm and
		 * used by master to look up memory created by
		 * slave
		 */
		int pid;
		int init_done;
	} slave;
} ODP_PACKED;

/* The maximum length of a ring name. */
#define _RING_NAMESIZE 32
/* If set - ring is visible from different processes.
 * Default is thread visible.*/
#define _RING_SHM_PROC (1 << 2)
/* Ring size mask */
#define _RING_SZ_MASK  (unsigned)(0x0fffffff)

typedef struct {
	/* Rings tailq lock */
	odp_rwlock_t qlock;
	odp_shm_t shm;
} global_data_t;

static global_data_t *global;

/* Initialize tailq_ring */
static int _ring_global_init(void)
{
	odp_shm_t shm;

	/* Allocate globally shared memory */
	shm = odp_shm_reserve("_odp_ring_global", sizeof(global_data_t),
			      ODP_CACHE_LINE_SIZE, 0);
	if (ODP_SHM_INVALID == shm) {
		ODP_ERR("Shm reserve failed for pktio ring\n");
		return -1;
	}

	global = odp_shm_addr(shm);
	memset(global, 0, sizeof(global_data_t));
	global->shm = shm;

	return 0;
}

static int _ring_global_term(void)
{
	if (odp_shm_free(global->shm)) {
		ODP_ERR("Shm free failed for pktio ring\n");
		return -1;
	}
	return 0;
}

/* create the ring */
static ring_ptr_t *
_ring_create(const char *name, unsigned count, unsigned flags)
{
	char ring_name[_RING_NAMESIZE];
	ring_ptr_t *r;
	size_t ring_size;
	uint32_t shm_flag;
	odp_shm_t shm;

	if (flags & _RING_SHM_PROC)
		shm_flag = ODP_SHM_PROC | ODP_SHM_EXPORT;
	else
		shm_flag = 0;
	if (odp_global_ro.shm_single_va)
		shm_flag |= ODP_SHM_SINGLE_VA;

	/* count must be a power of 2 */
	if (!CHECK_IS_POWER2(count)) {
		ODP_ERR("Requested size is invalid, must be power of 2,"
			"and do not exceed the size limit %u\n",
			_RING_SZ_MASK);
		__odp_errno = EINVAL;
		return NULL;
	}

	snprintf(ring_name, sizeof(ring_name), "%s", name);
	ring_size = sizeof(ring_ptr_t) + count * sizeof(void *);

	/* reserve a memory zone for this ring.*/
	shm = odp_shm_reserve(ring_name, ring_size, ODP_CACHE_LINE_SIZE,
			      shm_flag);

	r = odp_shm_addr(shm);
	if (r != NULL) {
		/* init the ring structure */
		ring_ptr_init(r);

	} else {
		__odp_errno = ENOMEM;
		ODP_ERR("Cannot reserve memory\n");
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
static unsigned _ring_count(ring_ptr_t *r, uint32_t mask)
{
	uint32_t prod_tail = odp_atomic_load_u32(&r->r.w_tail);
	uint32_t cons_tail = odp_atomic_load_u32(&r->r.r_tail);

	return (prod_tail - cons_tail) & mask;
}

/**
 * Return the number of free entries in a ring.
 */
static unsigned _ring_free_count(ring_ptr_t *r, uint32_t mask)
{
	uint32_t prod_tail = odp_atomic_load_u32(&r->r.w_tail);
	uint32_t cons_tail = odp_atomic_load_u32(&r->r.r_tail);

	return (cons_tail - prod_tail - 1) & mask;
}

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
	void		*pool_base;	/**< Remote pool base addr */
	void		*pool_mdata_base; /**< Remote pool mdata base addr */
	uint64_t	pkt_size;	/**< Packet size in remote pool */
	odp_pool_t	pool;		/**< Pool of main process */
	enum {
		PKTIO_TYPE_IPC_MASTER = 0, /**< Master is the process which
						creates shm */
		PKTIO_TYPE_IPC_SLAVE	   /**< Slave is the process which
						connects to shm */
	} type; /**< define if it's master or slave process */
	odp_atomic_u32_t ready; /**< 1 - pktio is ready and can recv/send
				     packet, 0 - not yet ready */
	void *pinfo;
	odp_shm_t pinfo_shm;
	odp_shm_t remote_pool_shm; /**< shm of remote pool get with
					_ipc_map_remote_pool() */
} pkt_ipc_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_ipc_t),
		  "PKTIO_PRIVATE_SIZE too small");

static inline pkt_ipc_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_ipc_t *)(uintptr_t)(pktio_entry->s.pkt_priv);
}

/* MAC address for the "ipc" interface */
static const char pktio_ipc_mac[] = {0x12, 0x12, 0x12, 0x12, 0x12, 0x12};

static odp_shm_t _ipc_map_remote_pool(const char *name, int pid);

static const char *_ipc_odp_buffer_pool_shm_name(odp_pool_t pool_hdl)
{
	pool_t *pool;
	odp_shm_t shm;
	odp_shm_info_t info;

	pool    = pool_entry_from_hdl(pool_hdl);
	shm = pool->shm;

	odp_shm_info(shm, &info);

	return info.name;
}

static int _ipc_master_start(pktio_entry_t *pktio_entry)
{
	struct pktio_info *pinfo = pkt_priv(pktio_entry)->pinfo;
	odp_shm_t shm;

	if (pinfo->slave.init_done == 0)
		return -1;

	shm = _ipc_map_remote_pool(pinfo->slave.pool_name,
				   pinfo->slave.pid);
	if (shm == ODP_SHM_INVALID) {
		ODP_DBG("no pool file %s for pid %d\n",
			pinfo->slave.pool_name, pinfo->slave.pid);
		return -1;
	}

	pkt_priv(pktio_entry)->remote_pool_shm = shm;
	pkt_priv(pktio_entry)->pool_base = odp_shm_addr(shm);
	pkt_priv(pktio_entry)->pool_mdata_base = (char *)odp_shm_addr(shm);

	odp_atomic_store_u32(&pkt_priv(pktio_entry)->ready, 1);

	IPC_ODP_DBG("%s started.\n",  pktio_entry->s.name);
	return 0;
}

static int _ipc_init_master(pktio_entry_t *pktio_entry,
			    const char *dev,
			    odp_pool_t pool_hdl)
{
	char ipc_shm_name[ODP_POOL_NAME_LEN + sizeof("_m_prod")];
	pool_t *pool;
	struct pktio_info *pinfo;
	const char *pool_name;

	pool = pool_entry_from_hdl(pool_hdl);
	(void)pool;

	if (strlen(dev) > (ODP_POOL_NAME_LEN - sizeof("_m_prod"))) {
		ODP_ERR("too big ipc name\n");
		return -1;
	}

	/* generate name in shm like ipc_pktio_r for
	 * to be processed packets ring.
	 */
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_prod", dev);
	pkt_priv(pktio_entry)->tx.send = _ring_create(ipc_shm_name,
						      PKTIO_IPC_ENTRIES,
						      _RING_SHM_PROC);
	if (!pkt_priv(pktio_entry)->tx.send) {
		ODP_ERR("pid %d unable to create ipc ring %s name\n",
			getpid(), ipc_shm_name);
		return -1;
	}
	ODP_DBG("Created IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pkt_priv(pktio_entry)->tx.send,
					  PKTIO_IPC_ENTRY_MASK),
		_ring_free_count(pkt_priv(pktio_entry)->tx.send,
				 PKTIO_IPC_ENTRY_MASK));

	/* generate name in shm like ipc_pktio_p for
	 * already processed packets
	 */
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_cons", dev);
	pkt_priv(pktio_entry)->tx.free = _ring_create(ipc_shm_name,
						      PKTIO_IPC_ENTRIES,
						      _RING_SHM_PROC);
	if (!pkt_priv(pktio_entry)->tx.free) {
		ODP_ERR("pid %d unable to create ipc ring %s name\n",
			getpid(), ipc_shm_name);
		goto free_m_prod;
	}
	ODP_DBG("Created IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pkt_priv(pktio_entry)->tx.free,
					  PKTIO_IPC_ENTRY_MASK),
		_ring_free_count(pkt_priv(pktio_entry)->tx.free,
				 PKTIO_IPC_ENTRY_MASK));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_prod", dev);
	pkt_priv(pktio_entry)->rx.recv = _ring_create(ipc_shm_name,
						      PKTIO_IPC_ENTRIES,
						      _RING_SHM_PROC);
	if (!pkt_priv(pktio_entry)->rx.recv) {
		ODP_ERR("pid %d unable to create ipc ring %s name\n",
			getpid(), ipc_shm_name);
		goto free_m_cons;
	}
	ODP_DBG("Created IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pkt_priv(pktio_entry)->rx.recv,
						   PKTIO_IPC_ENTRY_MASK),
		_ring_free_count(pkt_priv(pktio_entry)->rx.recv,
				 PKTIO_IPC_ENTRY_MASK));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_cons", dev);
	pkt_priv(pktio_entry)->rx.free = _ring_create(ipc_shm_name,
						      PKTIO_IPC_ENTRIES,
						      _RING_SHM_PROC);
	if (!pkt_priv(pktio_entry)->rx.free) {
		ODP_ERR("pid %d unable to create ipc ring %s name\n",
			getpid(), ipc_shm_name);
		goto free_s_prod;
	}
	ODP_DBG("Created IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pkt_priv(pktio_entry)->rx.free,
						   PKTIO_IPC_ENTRY_MASK),
		_ring_free_count(pkt_priv(pktio_entry)->rx.free,
				 PKTIO_IPC_ENTRY_MASK));

	/* Set up pool name for remote info */
	pinfo = pkt_priv(pktio_entry)->pinfo;
	pool_name = _ipc_odp_buffer_pool_shm_name(pool_hdl);
	if (strlen(pool_name) > ODP_POOL_NAME_LEN) {
		ODP_ERR("pid %d ipc pool name %s is too big %d\n",
			getpid(), pool_name, strlen(pool_name));
		goto free_s_prod;
	}

	memcpy(pinfo->master.pool_name, pool_name, strlen(pool_name));
	pinfo->slave.base_addr = 0;
	pinfo->slave.pid = 0;
	pinfo->slave.init_done = 0;

	pkt_priv(pktio_entry)->pool = pool_hdl;

	ODP_DBG("Pre init... DONE.\n");
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
	pool_t *pool = pool_entry_from_hdl(pool_hdl);

	snprintf(pinfo->slave.pool_name, ODP_POOL_NAME_LEN, "%s",
		 _ipc_odp_buffer_pool_shm_name(pool_hdl));
	pinfo->slave.pid = odp_global_ro.main_pid;
	pinfo->slave.block_size = pool->block_size;
	pinfo->slave.base_addr = pool->base_addr;
}

static odp_shm_t _ipc_map_remote_pool(const char *name, int pid)
{
	odp_shm_t shm;
	char rname[ODP_SHM_NAME_LEN];

	snprintf(rname, ODP_SHM_NAME_LEN, "remote-%s", name);
	shm = odp_shm_import(name, pid, rname);
	if (shm == ODP_SHM_INVALID) {
		ODP_ERR("unable map %s\n", name);
		return ODP_SHM_INVALID;
	}

	IPC_ODP_DBG("Mapped remote pool %s to local %s\n", name, rname);
	return shm;
}

static void *_ipc_shm_map(char *name, int pid)
{
	odp_shm_t shm;

	shm = odp_shm_import(name, pid, name);
	if (ODP_SHM_INVALID == shm) {
		ODP_ERR("unable to map: %s\n", name);
		return NULL;
	}

	return odp_shm_addr(shm);
}

static int _ipc_init_slave(const char *dev,
			   pktio_entry_t *pktio_entry,
			   odp_pool_t pool)
{
	if (strlen(dev) > (ODP_POOL_NAME_LEN - sizeof("_slave_r")))
		ODP_ABORT("too big ipc name\n");

	pkt_priv(pktio_entry)->pool = pool;
	return 0;
}

static int _ipc_slave_start(pktio_entry_t *pktio_entry)
{
	char ipc_shm_name[ODP_POOL_NAME_LEN + sizeof("_slave_r")];
	struct pktio_info *pinfo;
	odp_shm_t shm;
	char tail[ODP_POOL_NAME_LEN];
	char dev[ODP_POOL_NAME_LEN];
	int pid;

	if (sscanf(pktio_entry->s.name, "ipc:%d:%s", &pid, tail) != 2) {
		ODP_ERR("wrong pktio name\n");
		return -1;
	}

	sprintf(dev, "ipc:%s", tail);

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_prod", dev);
	pkt_priv(pktio_entry)->rx.recv  = _ipc_shm_map(ipc_shm_name, pid);
	if (!pkt_priv(pktio_entry)->rx.recv) {
		ODP_DBG("pid %d unable to find ipc ring %s name\n",
			getpid(), dev);
		sleep(1);
		return -1;
	}
	ODP_DBG("Connected IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pkt_priv(pktio_entry)->rx.recv,
					  PKTIO_IPC_ENTRY_MASK),
		_ring_free_count(pkt_priv(pktio_entry)->rx.recv,
				 PKTIO_IPC_ENTRY_MASK));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_cons", dev);
	pkt_priv(pktio_entry)->rx.free = _ipc_shm_map(ipc_shm_name, pid);
	if (!pkt_priv(pktio_entry)->rx.free) {
		ODP_ERR("pid %d unable to find ipc ring %s name\n",
			getpid(), dev);
		goto free_m_prod;
	}
	ODP_DBG("Connected IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pkt_priv(pktio_entry)->rx.free,
					  PKTIO_IPC_ENTRY_MASK),
		_ring_free_count(pkt_priv(pktio_entry)->rx.free,
				 PKTIO_IPC_ENTRY_MASK));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_prod", dev);
	pkt_priv(pktio_entry)->tx.send = _ipc_shm_map(ipc_shm_name, pid);
	if (!pkt_priv(pktio_entry)->tx.send) {
		ODP_ERR("pid %d unable to find ipc ring %s name\n",
			getpid(), dev);
		goto free_m_cons;
	}
	ODP_DBG("Connected IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pkt_priv(pktio_entry)->tx.send,
					  PKTIO_IPC_ENTRY_MASK),
		_ring_free_count(pkt_priv(pktio_entry)->tx.send,
				 PKTIO_IPC_ENTRY_MASK));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_cons", dev);
	pkt_priv(pktio_entry)->tx.free = _ipc_shm_map(ipc_shm_name, pid);
	if (!pkt_priv(pktio_entry)->tx.free) {
		ODP_ERR("pid %d unable to find ipc ring %s name\n",
			getpid(), dev);
		goto free_s_prod;
	}
	ODP_DBG("Connected IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pkt_priv(pktio_entry)->tx.free,
					  PKTIO_IPC_ENTRY_MASK),
		_ring_free_count(pkt_priv(pktio_entry)->tx.free,
				 PKTIO_IPC_ENTRY_MASK));

	/* Get info about remote pool */
	pinfo = pkt_priv(pktio_entry)->pinfo;
	shm = _ipc_map_remote_pool(pinfo->master.pool_name,
				   pid);
	pkt_priv(pktio_entry)->remote_pool_shm = shm;
	pkt_priv(pktio_entry)->pool_mdata_base = (char *)odp_shm_addr(shm);
	pkt_priv(pktio_entry)->pkt_size = pinfo->master.block_size;

	_ipc_export_pool(pinfo, pkt_priv(pktio_entry)->pool);

	odp_atomic_store_u32(&pkt_priv(pktio_entry)->ready, 1);
	pinfo->slave.init_done = 1;

	ODP_DBG("%s started.\n",  pktio_entry->s.name);
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
	int ret = -1;
	int pid;
	struct pktio_info *pinfo;
	char name[ODP_POOL_NAME_LEN + sizeof("_info")];
	char tail[ODP_POOL_NAME_LEN];
	odp_shm_t shm;

	ODP_STATIC_ASSERT(ODP_POOL_NAME_LEN == _RING_NAMESIZE,
			  "mismatch pool and ring name arrays");

	if (strncmp(dev, "ipc", 3))
		return -1;

	odp_atomic_init_u32(&pkt_priv(pktio_entry)->ready, 0);

	pkt_priv(pktio_entry)->rx.cache = _ring_create("ipc_rx_cache",
						       PKTIO_IPC_ENTRIES, 0);
	if (!pkt_priv(pktio_entry)->rx.cache)
		return -1;

	/* Shared info about remote pktio */
	if (sscanf(dev, "ipc:%d:%s", &pid, tail) == 2) {
		pkt_priv(pktio_entry)->type = PKTIO_TYPE_IPC_SLAVE;

		snprintf(name, sizeof(name), "ipc:%s_info", tail);
		IPC_ODP_DBG("lookup for name %s for pid %d\n", name, pid);
		shm = odp_shm_import(name, pid, name);
		if (ODP_SHM_INVALID == shm) {
			_ring_destroy("ipc_rx_cache");
			return -1;
		}
		pinfo = odp_shm_addr(shm);

		if (!pinfo->master.init_done) {
			odp_shm_free(shm);
			_ring_destroy("ipc_rx_cache");
			return -1;
		}
		pkt_priv(pktio_entry)->pinfo = pinfo;
		pkt_priv(pktio_entry)->pinfo_shm = shm;
		ODP_DBG("process %d is slave\n", getpid());
		ret = _ipc_init_slave(name, pktio_entry, pool);
	} else {
		pkt_priv(pktio_entry)->type = PKTIO_TYPE_IPC_MASTER;
		snprintf(name, sizeof(name), "%s_info", dev);
		shm = odp_shm_reserve(name, sizeof(struct pktio_info),
				      ODP_CACHE_LINE_SIZE,
				      ODP_SHM_EXPORT | ODP_SHM_SINGLE_VA);
		if (ODP_SHM_INVALID == shm) {
			_ring_destroy("ipc_rx_cache");
			ODP_ERR("can not create shm %s\n", name);
			return -1;
		}

		pinfo = odp_shm_addr(shm);
		pinfo->master.init_done = 0;
		pinfo->master.pool_name[0] = 0;
		pkt_priv(pktio_entry)->pinfo = pinfo;
		pkt_priv(pktio_entry)->pinfo_shm = shm;
		ODP_DBG("process %d is master\n", getpid());
		ret = _ipc_init_master(pktio_entry, dev, pool);
	}

	return ret;
}

static void _ipc_free_ring_packets(pktio_entry_t *pktio_entry, ring_ptr_t *r,
				   uint32_t r_mask)
{
	uintptr_t offsets[PKTIO_IPC_ENTRIES];
	int ret;
	void **rbuf_p;
	int i;
	void *addr;
	pool_t *pool;

	if (!r)
		return;

	pool = pool_entry_from_hdl(pkt_priv(pktio_entry)->pool);
	addr = odp_shm_addr(pool->shm);

	rbuf_p = (void *)&offsets;

	while (1) {
		ret = ring_ptr_deq_multi(r, r_mask, rbuf_p,
					 PKTIO_IPC_ENTRIES - 1);
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
	int pkts = 0;
	int i;
	ring_ptr_t *r;
	ring_ptr_t *r_p;
	uintptr_t offsets[PKTIO_IPC_ENTRIES];
	void **ipcbufs_p = (void *)&offsets[0];
	uint32_t ready;

	ready = odp_atomic_load_u32(&pkt_priv(pktio_entry)->ready);
	if (odp_unlikely(!ready)) {
		IPC_ODP_DBG("start pktio is missing before usage?\n");
		return 0;
	}

	_ipc_free_ring_packets(pktio_entry, pkt_priv(pktio_entry)->tx.free,
			       PKTIO_IPC_ENTRY_MASK);

	/* rx from cache */
	r = pkt_priv(pktio_entry)->rx.cache;
	pkts = ring_ptr_deq_multi(r, PKTIO_IPC_ENTRY_MASK, ipcbufs_p, len);
	if (odp_unlikely(pkts < 0))
		ODP_ABORT("internal error dequeue\n");

	/* rx from other app */
	if (pkts == 0) {
		ipcbufs_p = (void *)&offsets[0];
		r = pkt_priv(pktio_entry)->rx.recv;
		pkts = ring_ptr_deq_multi(r, PKTIO_IPC_ENTRY_MASK, ipcbufs_p,
					  len);
		if (odp_unlikely(pkts < 0))
			ODP_ABORT("internal error dequeue\n");
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

		phdr = (void *)((uint8_t *)pkt_priv(pktio_entry)->
				pool_mdata_base +
		       offsets[i]);

		pool = pkt_priv(pktio_entry)->pool;
		if (odp_unlikely(pool == ODP_POOL_INVALID))
			ODP_ABORT("invalid pool");

		data_pool_off = phdr->buf_hdr.ipc_data_offset;

		pkt = odp_packet_alloc(pool, phdr->frame_len);
		if (odp_unlikely(pkt == ODP_PACKET_INVALID)) {
			/* Original pool might be smaller then
			*  PKTIO_IPC_ENTRIES. If packet can not be
			 * allocated from pool at this time,
			 * simple get in on next recv() call. To keep
			 * packet ordering store such packets in local
			 * cache.
			 */
			IPC_ODP_DBG("unable to allocate packet %d/%d\n",
				    i, pkts);
			break;
		}

		/* Copy packet data. */
		pkt_data = odp_packet_data(pkt);
		if (odp_unlikely(!pkt_data))
			ODP_ABORT("unable to map pkt_data ipc_slave %d\n",
				  (PKTIO_TYPE_IPC_SLAVE ==
					pkt_priv(pktio_entry)->type));

		/* Copy packet data from shared pool to local pool. */
		rmt_data_ptr = (uint8_t *)pkt_priv(pktio_entry)->
				pool_mdata_base +
			       data_pool_off;
		memcpy(pkt_data, rmt_data_ptr, phdr->frame_len);

		/* Copy packets L2, L3 parsed offsets and size */
		copy_packet_cls_metadata(phdr, packet_hdr(pkt));

		packet_hdr(pkt)->frame_len = phdr->frame_len;
		packet_hdr(pkt)->headroom = phdr->headroom;
		packet_hdr(pkt)->tailroom = phdr->tailroom;

		/* Take classification fields */
		packet_hdr(pkt)->p = phdr->p;

		pkt_table[i] = pkt;
	}

	/* put back to rx ring dequed but not processed packets*/
	if (pkts != i) {
		ipcbufs_p = (void *)&offsets[i];
		r_p = pkt_priv(pktio_entry)->rx.cache;
		ring_ptr_enq_multi(r_p, PKTIO_IPC_ENTRY_MASK, ipcbufs_p,
				   pkts - i);

		if (i == 0)
			return 0;
	}

	/*num of actually received packets*/
	pkts = i;

	/* Now tell other process that we no longer need that buffers.*/
	r_p = pkt_priv(pktio_entry)->rx.free;

	ipcbufs_p = (void *)&offsets[0];
	ring_ptr_enq_multi(r_p, PKTIO_IPC_ENTRY_MASK, ipcbufs_p, pkts);

	for (i = 0; i < pkts; i++) {
		IPC_ODP_DBG("%d/%d send to be free packet offset %x\n",
			    i, pkts, offsets[i]);
	}

	return pkts;
}

static int ipc_pktio_recv(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			  odp_packet_t pkt_table[], int num)
{
	int ret;

	odp_ticketlock_lock(&pktio_entry->s.rxl);

	ret = ipc_pktio_recv_lockless(pktio_entry, pkt_table, num);

	odp_ticketlock_unlock(&pktio_entry->s.rxl);

	return ret;
}

static int ipc_pktio_send_lockless(pktio_entry_t *pktio_entry,
				   const odp_packet_t pkt_table[], int num)
{
	ring_ptr_t *r;
	void **rbuf_p;
	int i;
	uint32_t ready = odp_atomic_load_u32(&pkt_priv(pktio_entry)->ready);
	pool_t *ipc_pool = pool_entry_from_hdl(pkt_priv(pktio_entry)->pool);
	odp_packet_t pkt_table_mapped[num]; /**< Ready to send packet has to be
					      * in memory mapped pool. */
	uintptr_t offsets[num];

	if (odp_unlikely(!ready))
		return 0;

	_ipc_free_ring_packets(pktio_entry, pkt_priv(pktio_entry)->tx.free,
			       PKTIO_IPC_ENTRY_MASK);

	/* Copy packets to shm shared pool if they are in different
	 * pool, or if they are references (we can't share across IPC).
	 */
	for (i = 0; i < num; i++) {
		odp_packet_t pkt =  pkt_table[i];
		odp_packet_hdr_t *pkt_hdr;
		pool_t *pool;

		pkt_hdr = packet_hdr(pkt);
		pool = pkt_hdr->buf_hdr.pool_ptr;

		if (pool->pool_idx != ipc_pool->pool_idx ||
		    odp_packet_has_ref(pkt)) {
			odp_packet_t newpkt;

			newpkt = odp_packet_copy(pkt,
						 pkt_priv(pktio_entry)->pool);
			if (newpkt == ODP_PACKET_INVALID)
				ODP_ABORT("Unable to copy packet\n");

			odp_packet_free(pkt);
			pkt_table_mapped[i] = newpkt;
		} else {
			pkt_table_mapped[i] = pkt;
		}
	}

	/* Set offset to phdr for outgoing packets */
	for (i = 0; i < num; i++) {
		uint64_t data_pool_off;
		odp_packet_t pkt = pkt_table_mapped[i];
		odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
		odp_pool_t pool_hdl = odp_packet_pool(pkt);
		pool_t *pool = pool_entry_from_hdl(pool_hdl);

		offsets[i] = (uint8_t *)pkt_hdr -
			     (uint8_t *)odp_shm_addr(pool->shm);
		data_pool_off = (uint8_t *)pkt_hdr->seg_data -
				(uint8_t *)odp_shm_addr(pool->shm);

		/* compile all function code even if ipc disabled with config */
		pkt_hdr->buf_hdr.ipc_data_offset = data_pool_off;
		IPC_ODP_DBG("%d/%d send packet %llx, pool %llx,"
			    "phdr = %p, offset %x sendoff %x, addr %llx iaddr %llx\n",
			    i, num,
			    odp_packet_to_u64(pkt), odp_pool_to_u64(pool_hdl),
			    pkt_hdr, pkt_hdr->buf_hdr.ipc_data_offset,
			    offsets[i], odp_shm_addr(pool->shm),
			    odp_shm_addr(pool_entry_from_hdl(
					 pkt_priv(pktio_entry)->pool)->shm));
	}

	/* Put packets to ring to be processed by other process. */
	rbuf_p = (void *)&offsets[0];
	r = pkt_priv(pktio_entry)->tx.send;
	ring_ptr_enq_multi(r, PKTIO_IPC_ENTRY_MASK, rbuf_p, num);

	return num;
}

static int ipc_pktio_send(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			  const odp_packet_t pkt_table[], int num)
{
	int ret;

	odp_ticketlock_lock(&pktio_entry->s.txl);

	ret = ipc_pktio_send_lockless(pktio_entry, pkt_table, num);

	odp_ticketlock_unlock(&pktio_entry->s.txl);

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
	uint32_t ready = odp_atomic_load_u32(&pkt_priv(pktio_entry)->ready);

	if (ready) {
		ODP_ABORT("%s Already started\n", pktio_entry->s.name);
		return -1;
	}

	if (pkt_priv(pktio_entry)->type == PKTIO_TYPE_IPC_MASTER)
		return _ipc_master_start(pktio_entry);
	else
		return _ipc_slave_start(pktio_entry);
}

static int ipc_stop(pktio_entry_t *pktio_entry)
{
	odp_atomic_store_u32(&pkt_priv(pktio_entry)->ready, 0);

	if (pkt_priv(pktio_entry)->tx.send)
		_ipc_free_ring_packets(pktio_entry,
				       pkt_priv(pktio_entry)->tx.send,
				       PKTIO_IPC_ENTRY_MASK);
	/* other process can transfer packets from one ring to
	 * other, use delay here to free that packets. */
	sleep(1);
	if (pkt_priv(pktio_entry)->tx.free)
		_ipc_free_ring_packets(pktio_entry,
				       pkt_priv(pktio_entry)->tx.free,
				       PKTIO_IPC_ENTRY_MASK);

	return 0;
}

static int ipc_close(pktio_entry_t *pktio_entry)
{
	char ipc_shm_name[ODP_POOL_NAME_LEN + sizeof("_m_prod")];
	char *dev = pktio_entry->s.name;
	char name[ODP_POOL_NAME_LEN];
	char tail[ODP_POOL_NAME_LEN];
	int pid = 0;

	ipc_stop(pktio_entry);

	odp_shm_free(pkt_priv(pktio_entry)->remote_pool_shm);

	if (sscanf(dev, "ipc:%d:%s", &pid, tail) == 2)
		snprintf(name, sizeof(name), "ipc:%s", tail);
	else
		snprintf(name, sizeof(name), "%s", dev);

	/* unlink this pktio info for both master and slave */
	odp_shm_free(pkt_priv(pktio_entry)->pinfo_shm);

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

static int ipc_pktio_init_global(void)
{
	ODP_DBG("PKTIO: initializing ipc interface.\n");
	return _ring_global_init();
}

static int ipc_pktio_term_global(void)
{
	return _ring_global_term();
}

const pktio_if_ops_t ipc_pktio_ops = {
	.name = "ipc",
	.print = NULL,
	.init_global = ipc_pktio_init_global,
	.init_local = NULL,
	.term = ipc_pktio_term_global,
	.open = ipc_pktio_open,
	.close = ipc_close,
	.recv =  ipc_pktio_recv,
	.send = ipc_pktio_send,
	.start = ipc_start,
	.stop = ipc_stop,
	.mtu_get = ipc_mtu_get,
	.promisc_mode_set = NULL,
	.promisc_mode_get = NULL,
	.mac_get = ipc_mac_addr_get,
	.mac_set = NULL,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.config = NULL
};
