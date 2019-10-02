/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp/autoheader_internal.h>

#if defined(_ODP_PCAPNG) && _ODP_PCAPNG == 1

#include <odp_pcapng.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/shared_memory.h>
#include <odp_init_internal.h>
#include <odp_macros_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_posix_extensions.h>
#include <odp/api/spinlock.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/inotify.h>
#include <sys/select.h>

#define PCAPNG_BLOCK_TYPE_EPB 0x00000006UL
#define PCAPNG_BLOCK_TYPE_SHB 0x0A0D0D0AUL
#define PCAPNG_BLOCK_TYPE_IDB 0x00000001UL
#define PCAPNG_ENDIAN_MAGIC 0x1A2B3C4DUL
#define PCAPNG_DATA_ALIGN 4
#define PCAPNG_LINKTYPE_ETHERNET 0x1

/* inotify */
#define INOTIFY_BUF_LEN (16 * (sizeof(struct inotify_event)))
#define PCAPNG_WATCH_DIR "/var/run/odp/"

/* pcapng: enhanced packet block file encoding */
typedef struct ODP_PACKED pcapng_section_hdr_block_s {
	uint32_t block_type;
	uint32_t block_total_length;
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int64_t section_len;
	uint32_t block_total_length2;
} pcapng_section_hdr_block_t;

typedef struct pcapng_interface_description_block {
	uint32_t block_type;
	uint32_t block_total_length;
	uint16_t linktype;
	uint16_t reserved;
	uint32_t snaplen;
	uint32_t block_total_length2;
} pcapng_interface_description_block_t;

typedef struct pcapng_enhanced_packet_block_s {
	uint32_t block_type;
	uint32_t block_total_length;
	uint32_t interface_idx;
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	uint32_t captured_len;
	uint32_t packet_len;
} pcapng_enhanced_packet_block_t;

typedef struct ODP_ALIGNED_CACHE {
	odp_shm_t shm;
	pktio_entry_t *entry[ODP_CONFIG_PKTIO_ENTRIES];
	int num_entries;
	pthread_t inotify_thread;
	int inotify_fd;
	int inotify_watch_fd;
	int inotify_is_running;
	odp_spinlock_t lock;
} pcapng_global_t;

static pcapng_global_t *pcapng_gbl;

int write_pcapng_hdr(pktio_entry_t *entry, int qidx);

int _odp_pcapng_init_global(void)
{
	odp_shm_t shm;

	shm = odp_shm_reserve("_odp_pcapng_gbl", sizeof(pcapng_global_t),
			      ODP_PAGE_SIZE, 0);
	if (shm == ODP_SHM_INVALID)
		return -1;

	pcapng_gbl = odp_shm_addr(shm);

	memset(pcapng_gbl, 0, sizeof(pcapng_global_t));
	pcapng_gbl->shm = shm;

	odp_spinlock_init(&pcapng_gbl->lock);

	return 0;
}

int _odp_pcapng_term_global(void)
{
	int ret = 0;

	if (odp_shm_free(pcapng_gbl->shm)) {
		ODP_ERR("shm free failed");
		ret = -1;
	}

	return ret;
}

static void pcapng_drain_fifo(int fd)
{
	char buffer[4096];
	ssize_t len;

	do {
		len = read(fd, buffer, sizeof(buffer));
	} while (len > 0);
}

static void inotify_event_handle(pktio_entry_t *entry, int qidx,
				 struct inotify_event *event)
{
	int mtu = MAX(odp_pktin_maxlen(entry->s.handle),
		      odp_pktout_maxlen(entry->s.handle));

	if (event->mask & IN_OPEN) {
		int ret;

		if (PIPE_BUF < mtu + sizeof(pcapng_enhanced_packet_block_t) +
		    sizeof(uint32_t)) {
			ODP_ERR("PIPE_BUF:%d too small. Disabling pcap\n",
				PIPE_BUF);
			entry->s.pcapng.state[qidx] = PCAPNG_WR_STOP;

			return;
		}

		ret = write_pcapng_hdr(entry, qidx);
		if (ret) {
			entry->s.pcapng.state[qidx] = PCAPNG_WR_STOP;
		} else {
			entry->s.pcapng.state[qidx] = PCAPNG_WR_PKT;
			ODP_DBG("Open %s for pcap tracing\n", event->name);
		}
	} else if (event->mask & IN_CLOSE) {
		int fd = entry->s.pcapng.fd[qidx];

		pcapng_drain_fifo(fd);
		entry->s.pcapng.state[qidx] = PCAPNG_WR_STOP;
		ODP_DBG("Close %s for pcap tracing\n", event->name);
	} else {
		ODP_ERR("Unknown inotify event 0x%08x\n", event->mask);
	}
}

static void get_pcapng_fifo_name(char *pcapng_entry, size_t len,
				 char *pktio_name, int qidx)
{
	snprintf(pcapng_entry, len, "%d-%s-flow-%d",
		 odp_global_ro.main_pid, pktio_name, qidx);
	pcapng_entry[len - 1] = 0;
}

static int get_qidx_from_fifo(pktio_entry_t *entry, char *name)
{
	unsigned int max_queue =
		MAX(entry->s.num_in_queue, entry->s.num_out_queue);
	unsigned int i;

	for (i = 0; i < max_queue; i++) {
		char pcapng_entry[256];

		get_pcapng_fifo_name(pcapng_entry, sizeof(pcapng_entry),
				     entry->s.name, i);
		/*
		 * verify we still talk to a fifo before returning a valid
		 * queue number
		 */
		if (strcmp(name, pcapng_entry) == 0) {
			struct stat fstat;
			char pcapng_path[256];

			snprintf(pcapng_path, sizeof(pcapng_path), "%s/%s",
				 PCAPNG_WATCH_DIR, name);
			stat(pcapng_path, &fstat);

			return S_ISFIFO(fstat.st_mode) ? (int)i : -1;
		}
	}

	return -1;
}

static pktio_entry_t *pktio_from_event(struct inotify_event *event)
{
	int i;

	odp_spinlock_lock(&pcapng_gbl->lock);

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; i++) {
		pktio_entry_t *entry = pcapng_gbl->entry[i];

		if (entry == NULL)
			continue;

		if (get_qidx_from_fifo(entry, event->name) != -1) {
			odp_spinlock_unlock(&pcapng_gbl->lock);
			return entry;
		}
	}

	odp_spinlock_unlock(&pcapng_gbl->lock);

	return NULL;
}

static void *inotify_update(void *arg)
{
	struct timeval time;
	ssize_t rdlen;
	int offset;
	char buffer[INOTIFY_BUF_LEN];
	fd_set rfds;
	int inotify_fd = *(int *)arg;

	while (1) {
		offset = 0;
		FD_ZERO(&rfds);
		FD_SET(inotify_fd, &rfds);
		time.tv_sec = 2;
		time.tv_usec = 0;
		select(inotify_fd + 1, &rfds, NULL, NULL, &time);
		if (FD_ISSET(inotify_fd, &rfds)) {
			rdlen = read(inotify_fd, buffer, INOTIFY_BUF_LEN);
			while (offset < rdlen) {
				int qidx;
				struct inotify_event *event =
					(struct inotify_event *)(void *)
					 &buffer[offset];
				pktio_entry_t *entry;

				offset += sizeof(struct inotify_event) +
						event->len;

				entry = pktio_from_event(event);
				if (entry == NULL)
					continue;

				qidx = get_qidx_from_fifo(entry, event->name);
				if (qidx == -1)
					continue;

				inotify_event_handle(entry, qidx, event);
			}
		}
	}

	return NULL;
}

static int get_fifo_max_size(void)
{
	FILE *file;
	char buf[128];
	int ret = -1;

	file = fopen("/proc/sys/fs/pipe-max-size", "r");
	if (file == NULL)
		return ret;

	if (fgets(buf, sizeof(buf), file))
		ret = atoi(buf);

	fclose(file);

	return ret;
}

int _odp_pcapng_start(pktio_entry_t *entry)
{
	int ret = -1, fd;
	pthread_attr_t attr;
	unsigned int i;
	unsigned int max_queue =
		MAX(entry->s.num_in_queue, entry->s.num_out_queue);
	int fifo_sz;

	fifo_sz = get_fifo_max_size();
	if (fifo_sz < 0)
		ODP_DBG("failed to read max fifo size\n");

	for (i = 0; i < max_queue; i++) {
		char pcapng_name[128];
		char pcapng_path[256];

		entry->s.pcapng.fd[i] = -1;
		entry->s.pcapng.state[i] = PCAPNG_WR_STOP;

		get_pcapng_fifo_name(pcapng_name, sizeof(pcapng_name),
				     entry->s.name, i);
		snprintf(pcapng_path, sizeof(pcapng_path), "%s/%s",
			 PCAPNG_WATCH_DIR, pcapng_name);
		if (mkfifo(pcapng_path, O_RDWR)) {
			ODP_ERR("pcap not available for %s %s\n",
				pcapng_path, strerror(errno));
			continue;
		}

		if (chmod(pcapng_path, S_IRUSR | S_IRGRP))
			ODP_ERR("Failed to change file permission for %s %s\n",
				pcapng_path, strerror(errno));

		fd = open(pcapng_path, O_RDWR | O_NONBLOCK);
		if (fd == -1) {
			ODP_ERR("Fail to open fifo\n");
			entry->s.pcapng.state[i] = PCAPNG_WR_STOP;
			if (remove(pcapng_path) == -1)
				ODP_ERR("Can't remove fifo %s\n", pcapng_path);
			continue;
		}

		if (fifo_sz > 0) {
			if (fcntl(fd, F_SETPIPE_SZ, fifo_sz) != fifo_sz)
				ODP_DBG("Failed to set max fifo size\n");
			else
				ODP_DBG("set pcap fifo size %i\n", fifo_sz);
		}

		entry->s.pcapng.fd[i] = fd;
	}

	odp_spinlock_lock(&pcapng_gbl->lock);

	/* already running from a previous pktio */
	if (pcapng_gbl->inotify_is_running == 1) {
		pcapng_gbl->entry[odp_pktio_index(entry->s.handle)] = entry;
		pcapng_gbl->num_entries++;
		odp_spinlock_unlock(&pcapng_gbl->lock);
		return 0;
	}

	pcapng_gbl->inotify_fd = -1;
	pcapng_gbl->inotify_watch_fd = -1;

	pcapng_gbl->inotify_fd = inotify_init();
	if (pcapng_gbl->inotify_fd == -1) {
		ODP_ERR("can't init inotify. pcap disabled\n");
		goto out_destroy;
	}

	pcapng_gbl->inotify_watch_fd = inotify_add_watch(pcapng_gbl->inotify_fd,
							 PCAPNG_WATCH_DIR,
							 IN_CLOSE | IN_OPEN);

	if (pcapng_gbl->inotify_watch_fd == -1) {
		ODP_ERR("can't register inotify for %s. pcap disabled\n",
			strerror(errno));
		goto out_destroy;
	}

	/* create a thread to poll inotify triggers */
	pthread_attr_init(&attr);
	ret = pthread_create(&pcapng_gbl->inotify_thread, &attr, inotify_update,
			     &pcapng_gbl->inotify_fd);
	if (ret) {
		ODP_ERR("can't start inotify thread. pcap disabled\n");
	} else {
		pcapng_gbl->entry[odp_pktio_index(entry->s.handle)] = entry;
		pcapng_gbl->num_entries++;
		pcapng_gbl->inotify_is_running = 1;
	}

	odp_spinlock_unlock(&pcapng_gbl->lock);

	return ret;

out_destroy:
	odp_spinlock_unlock(&pcapng_gbl->lock);

	_odp_pcapng_stop(entry);

	return ret;
}

void _odp_pcapng_stop(pktio_entry_t *entry)
{
	int ret;
	unsigned int i;
	unsigned int max_queue =
		MAX(entry->s.num_in_queue, entry->s.num_out_queue);

	odp_spinlock_lock(&pcapng_gbl->lock);

	pcapng_gbl->entry[odp_pktio_index(entry->s.handle)] = NULL;
	pcapng_gbl->num_entries--;

	if (pcapng_gbl->inotify_is_running == 1 &&
	    pcapng_gbl->num_entries == 0) {
		ret = pthread_cancel(pcapng_gbl->inotify_thread);
		if (ret)
			ODP_ERR("can't cancel inotify thread %s\n",
				strerror(errno));
		pcapng_gbl->inotify_is_running = 0;
	}

	if (pcapng_gbl->num_entries == 0) {
		/* fd's will be -1 in case of any failure */
		ret = inotify_rm_watch(pcapng_gbl->inotify_fd,
				       pcapng_gbl->inotify_watch_fd);
		if (ret)
			ODP_ERR("can't deregister inotify %s\n",
				strerror(errno));

		if (pcapng_gbl->inotify_fd != -1)
			close(pcapng_gbl->inotify_fd);

		if (pcapng_gbl->inotify_watch_fd != -1)
			close(pcapng_gbl->inotify_watch_fd);
	}

	odp_spinlock_unlock(&pcapng_gbl->lock);

	for (i = 0; i < max_queue; i++) {
		char pcapng_name[128];
		char pcapng_path[256];

		entry->s.pcapng.state[i] = PCAPNG_WR_STOP;
		close(entry->s.pcapng.fd[i]);

		get_pcapng_fifo_name(pcapng_name, sizeof(pcapng_name),
				     entry->s.name, i);
		snprintf(pcapng_path, sizeof(pcapng_path), "%s/%s",
			 PCAPNG_WATCH_DIR, pcapng_name);

		if (remove(pcapng_path))
			ODP_ERR("can't delete fifo %s\n", pcapng_path);
	}
}

int write_pcapng_hdr(pktio_entry_t *entry, int qidx)
{
	size_t len;
	pcapng_section_hdr_block_t shb;
	pcapng_interface_description_block_t idb;
	int fd = entry->s.pcapng.fd[qidx];

	memset(&shb, 0, sizeof(shb));
	memset(&idb, 0, sizeof(idb));

	shb.block_type = PCAPNG_BLOCK_TYPE_SHB;
	shb.block_total_length = sizeof(shb);
	shb.block_total_length2 = sizeof(shb);
	shb.magic = PCAPNG_ENDIAN_MAGIC;
	shb.version_major = 0x1;
	shb.version_minor = 0x0;
	shb.section_len = -1;

	len = write(fd, &shb, sizeof(shb));
	/* fail to write shb/idb means the pcapng is unreadable */
	if (len != sizeof(shb)) {
		ODP_ERR("Failed to write pcapng section hdr\n");
		return -1;
	}
	fsync(fd);

	idb.block_type = PCAPNG_BLOCK_TYPE_IDB;
	idb.block_total_length = sizeof(idb);
	idb.block_total_length2 = sizeof(idb);
	idb.linktype = PCAPNG_LINKTYPE_ETHERNET;
	idb.snaplen = 0x0; /* unlimited */
	len = write(fd, &idb, sizeof(idb));
	if (len != sizeof(idb)) {
		ODP_ERR("Failed to write pcapng interface description\n");
		return -1;
	}
	fsync(fd);

	return 0;
}

/*
 * make sure that each fifo write is less than PIPE_BUF
 * this will make sure writes are atomic (on non blocking mode).
 * writev() transfers all the data and returns the number of bytes requested or
 * -EAGAIN
 */
static ssize_t write_fifo(int fd, struct iovec *iov, int iovcnt)
{
	ssize_t len = 0;

	len = writev(fd, iov, iovcnt);
	/*
	 * we don't care if a writev fails, we asynchronously read the fifo
	 * so the next block of packets might be successful. This error only
	 * means that some packets failed to append on the pcap file
	 */
	if (len > 0)
		fsync(fd);

	return len;
}

int _odp_pcapng_write_pkts(pktio_entry_t *entry, int qidx,
			   const odp_packet_t packets[], int num)
{
	int i = 0;
	struct iovec packet_iov[3 * num];
	pcapng_enhanced_packet_block_t epb[num];
	int iovcnt = 0;
	ssize_t block_len = 0;
	int fd = entry->s.pcapng.fd[qidx];
	ssize_t len = 0, wlen;

	for (i = 0; i < num; i++) {
		odp_packet_hdr_t *pkt_hdr = packet_hdr(packets[i]);
		uint32_t seg_len;
		char *buf = (char *)odp_packet_offset(packets[i], 0, &seg_len,
						      NULL);

		if (block_len + sizeof(epb[i]) +
		    ROUNDUP_ALIGN(seg_len, PCAPNG_DATA_ALIGN) +
		    sizeof(uint32_t) > PIPE_BUF) {
			wlen = write_fifo(fd, packet_iov, iovcnt);
			if (wlen > 0) {
				len += wlen;
				block_len = 0;
				iovcnt = 0;
			}
		}
		epb[i].block_type = PCAPNG_BLOCK_TYPE_EPB;
		epb[i].block_total_length = sizeof(epb[i]) +
			ROUNDUP_ALIGN(seg_len, PCAPNG_DATA_ALIGN) +
			PCAPNG_DATA_ALIGN;
		epb[i].interface_idx = 0;
		epb[i].timestamp_high =
			(uint32_t)(pkt_hdr->timestamp.u64 >> 32);
		epb[i].timestamp_low = (uint32_t)(pkt_hdr->timestamp.u64);
		epb[i].captured_len = seg_len;
		epb[i].packet_len = seg_len;

		/* epb */
		packet_iov[iovcnt].iov_base = &epb[i];
		packet_iov[iovcnt].iov_len = sizeof(epb[i]);
		block_len += packet_iov[iovcnt].iov_len;
		iovcnt++;

		/* data */
		packet_iov[iovcnt].iov_base = buf;
		packet_iov[iovcnt].iov_len =
			ROUNDUP_ALIGN(seg_len, PCAPNG_DATA_ALIGN);
		block_len += packet_iov[iovcnt].iov_len;
		iovcnt++;

		/* trailing */
		packet_iov[iovcnt].iov_base = &epb[i].block_total_length;
		packet_iov[iovcnt].iov_len = sizeof(uint32_t);
		block_len += packet_iov[iovcnt].iov_len;
		iovcnt++;
	}

	if (iovcnt) {
		wlen = write_fifo(fd, packet_iov, iovcnt);
		if (wlen > 0)
			len += wlen;
	}

	return len;
}

#endif /* _ODP_PCAPNG */
