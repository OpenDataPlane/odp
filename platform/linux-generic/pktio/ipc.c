/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_packet_io_ipc_internal.h>
#include <odp_debug_internal.h>
#include <odp_packet_io_internal.h>
#include <odp/api/system_info.h>
#include <odp_shm_internal.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

/* MAC address for the "ipc" interface */
static const char pktio_ipc_mac[] = {0x12, 0x12, 0x12, 0x12, 0x12, 0x12};

static void *_ipc_map_remote_pool(const char *name, size_t size);

static const char *_ipc_odp_buffer_pool_shm_name(odp_pool_t pool_hdl)
{
	pool_entry_t *pool;
	uint32_t pool_id;
	odp_shm_t shm;
	odp_shm_info_t info;

	pool_id = pool_handle_to_index(pool_hdl);
	pool    = get_pool_entry(pool_id);
	shm = pool->s.pool_shm;

	odp_shm_info(shm, &info);

	return info.name;
}

/**
* Look up for shared memory object.
*
* @param name   name of shm object
*
* @return 0 on success, otherwise non-zero
*/
static int _ipc_shm_lookup(const char *name)
{
	int shm;
	char shm_devname[SHM_DEVNAME_MAXLEN];

	if (!odp_global_data.ipc_ns)
		ODP_ABORT("ipc_ns not set\n");

	snprintf(shm_devname, SHM_DEVNAME_MAXLEN,
		 SHM_DEVNAME_FORMAT,
		 odp_global_data.ipc_ns, name);

	shm = shm_open(shm_devname, O_RDWR, S_IRUSR | S_IWUSR);
	if (shm == -1) {
		if (errno == ENOENT) {
			ODP_DBG("no file %s\n", shm_devname);
			return -1;
		}
		ODP_ABORT("shm_open for %s err %s\n",
			  shm_devname, strerror(errno));
	}
	close(shm);
	return 0;
}

static int _ipc_map_pktio_info(pktio_entry_t *pktio_entry,
			       const char *dev,
			       int *slave)
{
	struct pktio_info *pinfo;
	char name[ODP_POOL_NAME_LEN + sizeof("_info")];
	uint32_t flags;
	odp_shm_t shm;

	/* Create info about remote pktio */
	snprintf(name, sizeof(name), "%s_info", dev);

	flags = ODP_SHM_PROC | _ODP_SHM_O_EXCL;

	shm = odp_shm_reserve(name, sizeof(struct pktio_info),
			      ODP_CACHE_LINE_SIZE,
			      flags);
	if (ODP_SHM_INVALID != shm) {
		pinfo = odp_shm_addr(shm);
		pinfo->master.pool_name[0] = 0;
		*slave = 0;
	} else {
		flags = _ODP_SHM_PROC_NOCREAT | _ODP_SHM_O_EXCL;
		shm = odp_shm_reserve(name, sizeof(struct pktio_info),
				      ODP_CACHE_LINE_SIZE,
				      flags);
		if (ODP_SHM_INVALID == shm)
			ODP_ABORT("can not connect to shm\n");

		pinfo = odp_shm_addr(shm);
		*slave = 1;
	}

	pktio_entry->s.ipc.pinfo = pinfo;
	pktio_entry->s.ipc.pinfo_shm = shm;

	return 0;
}

static int _ipc_master_start(pktio_entry_t *pktio_entry)
{
	struct pktio_info *pinfo = pktio_entry->s.ipc.pinfo;
	int ret;
	void *ipc_pool_base;

	if (pinfo->slave.mdata_offset == 0)
		return -1;

	ret = _ipc_shm_lookup(pinfo->slave.pool_name);
	if (ret) {
		ODP_DBG("no pool file %s\n", pinfo->slave.pool_name);
		return -1;
	}

	ipc_pool_base = _ipc_map_remote_pool(pinfo->slave.pool_name,
					     pinfo->master.shm_pkt_pool_size);
	pktio_entry->s.ipc.pool_mdata_base = (char *)ipc_pool_base +
					     pinfo->slave.mdata_offset;

	odp_atomic_store_u32(&pktio_entry->s.ipc.ready, 1);

	ODP_DBG("%s started.\n",  pktio_entry->s.name);
	return 0;
}

static int _ipc_init_master(pktio_entry_t *pktio_entry,
			    const char *dev,
			    odp_pool_t pool)
{
	char ipc_shm_name[ODP_POOL_NAME_LEN + sizeof("_m_prod")];
	pool_entry_t *pool_entry;
	uint32_t pool_id;
	struct pktio_info *pinfo;
	const char *pool_name;
	odp_shm_t shm;

	pool_id = pool_handle_to_index(pool);
	pool_entry    = get_pool_entry(pool_id);

	if (strlen(dev) > (ODP_POOL_NAME_LEN - sizeof("_m_prod"))) {
		ODP_DBG("too big ipc name\n");
		return -1;
	}

	/* generate name in shm like ipc_pktio_r for
	 * to be processed packets ring.
	 */
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_prod", dev);
	pktio_entry->s.ipc.tx.send = _ring_create(ipc_shm_name,
			PKTIO_IPC_ENTRIES,
			_RING_SHM_PROC | _RING_NO_LIST);
	if (!pktio_entry->s.ipc.tx.send) {
		ODP_DBG("pid %d unable to create ipc ring %s name\n",
			getpid(), ipc_shm_name);
		return -1;
	}
	ODP_DBG("Created IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pktio_entry->s.ipc.tx.send),
		_ring_free_count(pktio_entry->s.ipc.tx.send));

	/* generate name in shm like ipc_pktio_p for
	 * already processed packets
	 */
	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_cons", dev);
	pktio_entry->s.ipc.tx.free = _ring_create(ipc_shm_name,
			PKTIO_IPC_ENTRIES,
			_RING_SHM_PROC | _RING_NO_LIST);
	if (!pktio_entry->s.ipc.tx.free) {
		ODP_DBG("pid %d unable to create ipc ring %s name\n",
			getpid(), ipc_shm_name);
		goto free_m_prod;
	}
	ODP_DBG("Created IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pktio_entry->s.ipc.tx.free),
		_ring_free_count(pktio_entry->s.ipc.tx.free));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_prod", dev);
	pktio_entry->s.ipc.rx.recv = _ring_create(ipc_shm_name,
			PKTIO_IPC_ENTRIES,
			_RING_SHM_PROC | _RING_NO_LIST);
	if (!pktio_entry->s.ipc.rx.recv) {
		ODP_DBG("pid %d unable to create ipc ring %s name\n",
			getpid(), ipc_shm_name);
		goto free_m_cons;
	}
	ODP_DBG("Created IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pktio_entry->s.ipc.rx.recv),
		_ring_free_count(pktio_entry->s.ipc.rx.recv));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_cons", dev);
	pktio_entry->s.ipc.rx.free = _ring_create(ipc_shm_name,
			PKTIO_IPC_ENTRIES,
			_RING_SHM_PROC | _RING_NO_LIST);
	if (!pktio_entry->s.ipc.rx.free) {
		ODP_DBG("pid %d unable to create ipc ring %s name\n",
			getpid(), ipc_shm_name);
		goto free_s_prod;
	}
	ODP_DBG("Created IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pktio_entry->s.ipc.rx.free),
		_ring_free_count(pktio_entry->s.ipc.rx.free));

	/* Set up pool name for remote info */
	pinfo = pktio_entry->s.ipc.pinfo;
	pool_name = _ipc_odp_buffer_pool_shm_name(pool);
	memcpy(pinfo->master.pool_name, pool_name, strlen(pool_name));
	pinfo->master.shm_pkt_pool_size = pool_entry->s.pool_size;
	pinfo->master.shm_pool_bufs_num = pool_entry->s.buf_num;
	pinfo->master.shm_pkt_size = pool_entry->s.seg_size;
	pinfo->master.mdata_offset =  pool_entry->s.pool_mdata_addr -
			       pool_entry->s.pool_base_addr;
	pinfo->slave.mdata_offset = 0;

	pktio_entry->s.ipc.pool = pool;

	ODP_DBG("Pre init... DONE.\n");

	_ipc_master_start(pktio_entry);

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

static void _ipc_export_pool(struct pktio_info *pinfo,
			     odp_pool_t pool)
{
	pool_entry_t *pool_entry;

	pool_entry = odp_pool_to_entry(pool);
	if (pool_entry->s.blk_size != pinfo->master.shm_pkt_size)
		ODP_ABORT("pktio for same name should have the same pool size\n");
	if (pool_entry->s.buf_num != (unsigned)pinfo->master.shm_pool_bufs_num)
		ODP_ABORT("pktio for same name should have the same pool size\n");

	snprintf(pinfo->slave.pool_name, ODP_POOL_NAME_LEN, "%s",
		 pool_entry->s.name);
	pinfo->slave.mdata_offset = pool_entry->s.pool_mdata_addr -
				    pool_entry->s.pool_base_addr;
}

static void *_ipc_map_remote_pool(const char *name, size_t size)
{
	odp_shm_t shm;
	void *addr;

	ODP_DBG("Mapping remote pool %s, size %ld\n", name, size);
	shm = odp_shm_reserve(name,
			      size,
			      ODP_CACHE_LINE_SIZE,
			      _ODP_SHM_PROC_NOCREAT);
	if (shm == ODP_SHM_INVALID)
		ODP_ABORT("unable map %s\n", name);

	addr = odp_shm_addr(shm);
	ODP_DBG("MAP master: %p - %p size %ld, pool %s\n",
		addr, (char *)addr + size, size, name);
	return addr;
}

static void *_ipc_shm_map(char *name, size_t size)
{
	odp_shm_t shm;
	int ret;

	ret = _ipc_shm_lookup(name);
	if (ret == -1)
		return NULL;

	shm = odp_shm_reserve(name, size,
			      ODP_CACHE_LINE_SIZE,
			      _ODP_SHM_PROC_NOCREAT);
	if (ODP_SHM_INVALID == shm)
		ODP_ABORT("unable to map: %s\n", name);

	return odp_shm_addr(shm);
}

static int _ipc_init_slave(const char *dev,
			   pktio_entry_t *pktio_entry,
			   odp_pool_t pool)
{
	if (strlen(dev) > (ODP_POOL_NAME_LEN - sizeof("_slave_r")))
		ODP_ABORT("too big ipc name\n");

	pktio_entry->s.ipc.pool = pool;
	return 0;
}

static int _ipc_slave_start(pktio_entry_t *pktio_entry)
{
	char ipc_shm_name[ODP_POOL_NAME_LEN + sizeof("_slave_r")];
	size_t ring_size = PKTIO_IPC_ENTRIES * sizeof(void *) +
			   sizeof(_ring_t);
	struct pktio_info *pinfo;
	void *ipc_pool_base;
	odp_shm_t shm;
	const char *dev = pktio_entry->s.name;

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_prod", dev);
	pktio_entry->s.ipc.rx.recv  = _ipc_shm_map(ipc_shm_name, ring_size);
	if (!pktio_entry->s.ipc.rx.recv) {
		ODP_DBG("pid %d unable to find ipc ring %s name\n",
			getpid(), dev);
		sleep(1);
		return -1;
	}
	ODP_DBG("Connected IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pktio_entry->s.ipc.rx.recv),
		_ring_free_count(pktio_entry->s.ipc.rx.recv));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_cons", dev);
	pktio_entry->s.ipc.rx.free = _ipc_shm_map(ipc_shm_name, ring_size);
	if (!pktio_entry->s.ipc.rx.free) {
		ODP_DBG("pid %d unable to find ipc ring %s name\n",
			getpid(), dev);
		goto free_m_prod;
	}
	ODP_DBG("Connected IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pktio_entry->s.ipc.rx.free),
		_ring_free_count(pktio_entry->s.ipc.rx.free));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_prod", dev);
	pktio_entry->s.ipc.tx.send = _ipc_shm_map(ipc_shm_name, ring_size);
	if (!pktio_entry->s.ipc.tx.send) {
		ODP_DBG("pid %d unable to find ipc ring %s name\n",
			getpid(), dev);
		goto free_m_cons;
	}
	ODP_DBG("Connected IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pktio_entry->s.ipc.tx.send),
		_ring_free_count(pktio_entry->s.ipc.tx.send));

	snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_cons", dev);
	pktio_entry->s.ipc.tx.free = _ipc_shm_map(ipc_shm_name, ring_size);
	if (!pktio_entry->s.ipc.tx.free) {
		ODP_DBG("pid %d unable to find ipc ring %s name\n",
			getpid(), dev);
		goto free_s_prod;
	}
	ODP_DBG("Connected IPC ring: %s, count %d, free %d\n",
		ipc_shm_name, _ring_count(pktio_entry->s.ipc.tx.free),
		_ring_free_count(pktio_entry->s.ipc.tx.free));

	/* Get info about remote pool */
	pinfo = pktio_entry->s.ipc.pinfo;
	ipc_pool_base = _ipc_map_remote_pool(pinfo->master.pool_name,
					     pinfo->master.shm_pkt_pool_size);
	pktio_entry->s.ipc.pool_mdata_base = (char *)ipc_pool_base +
					     pinfo->master.mdata_offset;
	pktio_entry->s.ipc.pkt_size = pinfo->master.shm_pkt_size;

	/* @todo: to simplify in linux-generic implementation we create pool for
	 * packets from IPC queue. On receive implementation copies packets to
	 * that pool. Later we can try to reuse original pool without packets
	 * copying. (pkt refcounts needs to be implemented).
	 */
	_ipc_export_pool(pinfo, pktio_entry->s.ipc.pool);

	odp_atomic_store_u32(&pktio_entry->s.ipc.ready, 1);

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
	int slave;

	ODP_STATIC_ASSERT(ODP_POOL_NAME_LEN == _RING_NAMESIZE,
			  "mismatch pool and ring name arrays");

	if (strncmp(dev, "ipc", 3))
		return -1;

	odp_atomic_init_u32(&pktio_entry->s.ipc.ready, 0);

	_ipc_map_pktio_info(pktio_entry, dev, &slave);
	pktio_entry->s.ipc.type = (slave == 0) ? PKTIO_TYPE_IPC_MASTER :
						 PKTIO_TYPE_IPC_SLAVE;

	if (pktio_entry->s.ipc.type == PKTIO_TYPE_IPC_MASTER) {
		ODP_DBG("process %d is master\n", getpid());
		ret = _ipc_init_master(pktio_entry, dev, pool);
	} else {
		ODP_DBG("process %d is slave\n", getpid());
		ret = _ipc_init_slave(dev, pktio_entry, pool);
	}

	return ret;
}

static inline void *_ipc_buffer_map(odp_buffer_hdr_t *buf,
				    uint32_t offset,
				    uint32_t *seglen,
				    uint32_t limit)
{
	int seg_index  = offset / buf->segsize;
	int seg_offset = offset % buf->segsize;
	void *addr = (char *)buf - buf->ipc_addr_offset[seg_index];

	if (seglen) {
		uint32_t buf_left = limit - offset;
		*seglen = seg_offset + buf_left <= buf->segsize ?
			buf_left : buf->segsize - seg_offset;
	}

	return (void *)(seg_offset + (uint8_t *)addr);
}

static inline void *_ipc_packet_map(odp_packet_hdr_t *pkt_hdr,
				    uint32_t offset, uint32_t *seglen)
{
	if (offset > pkt_hdr->frame_len)
		return NULL;

	return _ipc_buffer_map(&pkt_hdr->buf_hdr,
			  pkt_hdr->headroom + offset, seglen,
			  pkt_hdr->headroom + pkt_hdr->frame_len);
}

static void _ipc_free_ring_packets(_ring_t *r)
{
	odp_packet_t r_p_pkts[PKTIO_IPC_ENTRIES];
	int ret;
	void **rbuf_p;
	int i;

	rbuf_p = (void *)&r_p_pkts;

	while (1) {
		ret = _ring_mc_dequeue_burst(r, rbuf_p,
					     PKTIO_IPC_ENTRIES);
		if (0 == ret)
			break;
		for (i = 0; i < ret; i++) {
			if (r_p_pkts[i] != ODP_PACKET_INVALID)
				odp_packet_free(r_p_pkts[i]);
		}
	}
}

static int ipc_pktio_recv(pktio_entry_t *pktio_entry,
			  odp_packet_t pkt_table[], unsigned len)
{
	int pkts = 0;
	int i;
	_ring_t *r;
	_ring_t *r_p;

	odp_packet_t remote_pkts[PKTIO_IPC_ENTRIES];
	void **ipcbufs_p = (void *)&remote_pkts;
	uint32_t ready = odp_atomic_load_u32(&pktio_entry->s.ipc.ready);

	if (odp_unlikely(!ready)) {
		ODP_DBG("start pktio is missing before usage?\n");
		return -1;
	}

	_ipc_free_ring_packets(pktio_entry->s.ipc.tx.free);

	r = pktio_entry->s.ipc.rx.recv;
	pkts = _ring_mc_dequeue_burst(r, ipcbufs_p, len);
	if (odp_unlikely(pkts < 0))
		ODP_ABORT("error to dequeue no packets\n");

	/* fast path */
	if (odp_likely(0 == pkts))
		return 0;

	for (i = 0; i < pkts; i++) {
		odp_pool_t pool;
		odp_packet_t pkt;
		odp_packet_hdr_t phdr;
		void *ptr;
		odp_buffer_bits_t handle;
		int idx; /* Remote packet has coded pool and index.
			  * We need only index.*/
		void *pkt_data;
		void *remote_pkt_data;

		if (remote_pkts[i] == ODP_PACKET_INVALID)
			continue;

		handle.handle = _odp_packet_to_buffer(remote_pkts[i]);
		idx = handle.index;

		/* Link to packed data. To this line we have Zero-Copy between
		 * processes, to simplify use packet copy in that version which
		 * can be removed later with more advance buffer management
		 * (ref counters).
		 */
		/* reverse odp_buf_to_hdr() */
		ptr = (char *)pktio_entry->s.ipc.pool_mdata_base +
		      (idx * ODP_CACHE_LINE_SIZE);
		memcpy(&phdr, ptr, sizeof(odp_packet_hdr_t));

		/* Allocate new packet. Select*/
		pool = pktio_entry->s.ipc.pool;
		if (odp_unlikely(pool == ODP_POOL_INVALID))
			ODP_ABORT("invalid pool");

		pkt = odp_packet_alloc(pool, phdr.frame_len);
		if (odp_unlikely(pkt == ODP_PACKET_INVALID)) {
			/* Original pool might be smaller then
			*  PKTIO_IPC_ENTRIES. If packet can not be
			 * allocated from pool at this time,
			 * simple get in on next recv() call.
			 */
			if (i == 0)
				return 0;
			break;
		}

		/* Copy packet data. */
		pkt_data = odp_packet_data(pkt);
		if (odp_unlikely(!pkt_data))
			ODP_ABORT("unable to map pkt_data ipc_slave %d\n",
				  (PKTIO_TYPE_IPC_SLAVE ==
					pktio_entry->s.ipc.type));

		remote_pkt_data = _ipc_packet_map(ptr, 0, NULL);
		if (odp_unlikely(!remote_pkt_data))
			ODP_ABORT("unable to map remote_pkt_data, ipc_slave %d\n",
				  (PKTIO_TYPE_IPC_SLAVE ==
					pktio_entry->s.ipc.type));

		/* @todo fix copy packet!!! */
		memcpy(pkt_data, remote_pkt_data, phdr.frame_len);

		/* Copy packets L2, L3 parsed offsets and size */
		copy_packet_parser_metadata(&phdr, odp_packet_hdr(pkt));

		odp_packet_hdr(pkt)->frame_len = phdr.frame_len;
		odp_packet_hdr(pkt)->headroom = phdr.headroom;
		odp_packet_hdr(pkt)->tailroom = phdr.tailroom;
		pkt_table[i] = pkt;
	}

	/* Now tell other process that we no longer need that buffers.*/
	r_p = pktio_entry->s.ipc.rx.free;
	pkts = _ring_mp_enqueue_burst(r_p, ipcbufs_p, i);
	if (odp_unlikely(pkts < 0))
		ODP_ABORT("ipc: odp_ring_mp_enqueue_bulk r_p fail\n");

	return pkts;
}

static int ipc_pktio_send(pktio_entry_t *pktio_entry,
			  const odp_packet_t pkt_table[], unsigned len)
{
	_ring_t *r;
	void **rbuf_p;
	int ret;
	unsigned i;
	uint32_t ready = odp_atomic_load_u32(&pktio_entry->s.ipc.ready);
	odp_packet_t pkt_table_mapped[len]; /**< Ready to send packet has to be
					      * in memory mapped pool. */

	if (odp_unlikely(!ready))
		return 0;

	_ipc_free_ring_packets(pktio_entry->s.ipc.tx.free);

	/* Prepare packets: calculate offset from address. */
	for (i = 0; i < len; i++) {
		int j;
		odp_packet_t pkt =  pkt_table[i];
		odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
		odp_buffer_bits_t handle;
		uint32_t cur_mapped_pool_id =
			 pool_handle_to_index(pktio_entry->s.ipc.pool);
		uint32_t pool_id;

		/* do copy if packet was allocated from not mapped pool */
		handle.handle = _odp_packet_to_buffer(pkt);
		pool_id = handle.pool_id;
		if (pool_id != cur_mapped_pool_id) {
			odp_packet_t newpkt;

			newpkt = odp_packet_copy(pkt, pktio_entry->s.ipc.pool);
			if (newpkt == ODP_PACKET_INVALID)
				ODP_ABORT("Unable to copy packet\n");

			odp_packet_free(pkt);
			pkt_table_mapped[i] = newpkt;
		} else {
			pkt_table_mapped[i] = pkt;
		}

		rbuf_p = (void *)&pkt;

		/* buf_hdr.addr can not be used directly in remote process,
		 * convert it to offset
		 */
		for (j = 0; j < ODP_BUFFER_MAX_SEG; j++) {
			pkt_hdr->buf_hdr.ipc_addr_offset[j] = (char *)pkt_hdr -
				(char *)pkt_hdr->buf_hdr.addr[j];
		}
	}

	/* Put packets to ring to be processed by other process. */
	rbuf_p = (void *)&pkt_table_mapped[0];
	r = pktio_entry->s.ipc.tx.send;
	ret = _ring_mp_enqueue_burst(r, rbuf_p, len);
	if (odp_unlikely(ret < 0)) {
		ODP_ERR("pid %d odp_ring_mp_enqueue_bulk fail, ipc_slave %d, ret %d\n",
			getpid(),
			(PKTIO_TYPE_IPC_SLAVE == pktio_entry->s.ipc.type),
			ret);
		ODP_ERR("odp_ring_full: %d, odp_ring_count %d, _ring_free_count %d\n",
			_ring_full(r), _ring_count(r),
			_ring_free_count(r));
	}

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
	uint32_t ready = odp_atomic_load_u32(&pktio_entry->s.ipc.ready);

	if (ready) {
		ODP_ABORT("%s Already started\n", pktio_entry->s.name);
		return -1;
	}

	if (pktio_entry->s.ipc.type == PKTIO_TYPE_IPC_MASTER)
		return _ipc_master_start(pktio_entry);
	else
		return _ipc_slave_start(pktio_entry);
}

static int ipc_stop(pktio_entry_t *pktio_entry)
{
	odp_atomic_store_u32(&pktio_entry->s.ipc.ready, 0);

	_ipc_free_ring_packets(pktio_entry->s.ipc.tx.send);
	/* other process can transfer packets from one ring to
	 * other, use delay here to free that packets. */
	sleep(1);
	_ipc_free_ring_packets(pktio_entry->s.ipc.tx.free);

	return 0;
}

static int ipc_close(pktio_entry_t *pktio_entry)
{
	ipc_stop(pktio_entry);

	if (pktio_entry->s.ipc.type == PKTIO_TYPE_IPC_MASTER) {
		char ipc_shm_name[ODP_POOL_NAME_LEN + sizeof("_m_prod")];
		char *dev = pktio_entry->s.name;
		odp_shm_t shm;

		/* unlink this pktio info */
		odp_shm_free(pktio_entry->s.ipc.pinfo_shm);

		/* unlink rings */
		snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_cons", dev);
		shm = odp_shm_lookup(ipc_shm_name);
		odp_shm_free(shm);
		snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_s_prod", dev);
		shm = odp_shm_lookup(ipc_shm_name);
		odp_shm_free(shm);
		snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_cons", dev);
		shm = odp_shm_lookup(ipc_shm_name);
		odp_shm_free(shm);
		snprintf(ipc_shm_name, sizeof(ipc_shm_name), "%s_m_prod", dev);
		shm = odp_shm_lookup(ipc_shm_name);
		odp_shm_free(shm);
	}

	return 0;
}

const pktio_if_ops_t ipc_pktio_ops = {
	.name = "ipc",
	.init_global = NULL,
	.init_local = NULL,
	.term = NULL,
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
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.config = NULL
};
