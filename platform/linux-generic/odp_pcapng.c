/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#if defined(_ODP_PCAPNG) && _ODP_PCAPNG == 1

#include <odp_macros_internal.h>
#include <odp_packet_io_internal.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp_posix_extensions.h>
#include <odp_pcapng.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/inotify.h>
#include <sys/select.h>

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
		 odp_global_data.main_pid, pktio_name, qidx);
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

static void *inotify_update(void *arg)
{
	pktio_entry_t *entry = (pktio_entry_t *)arg;
	struct timeval time;
	ssize_t rdlen;
	int offset;
	char buffer[INOTIFY_BUF_LEN];
	fd_set rfds;

	while (1) {
		offset = 0;
		FD_ZERO(&rfds);
		FD_SET(odp_global_data.inotify_pcapng_fd, &rfds);
		time.tv_sec = 2;
		time.tv_usec = 0;
		select(odp_global_data.inotify_pcapng_fd + 1, &rfds, NULL,
		       NULL, &time);
		if (FD_ISSET(odp_global_data.inotify_pcapng_fd, &rfds)) {
			rdlen = read(odp_global_data.inotify_pcapng_fd,
				     buffer, INOTIFY_BUF_LEN);
			while (offset < rdlen) {
				int qidx;
				struct inotify_event *event =
					(struct inotify_event *)(void *)
					 &buffer[offset];

				qidx = get_qidx_from_fifo(entry, event->name);
				if (qidx == -1) {
					offset += sizeof(struct inotify_event) +
						event->len;
					continue;
				}

				inotify_event_handle(entry, qidx, event);
				offset += sizeof(struct inotify_event) +
						 event->len;
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

int pcapng_prepare(pktio_entry_t *entry)
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

	/* already running from a previous pktio */
	if (odp_global_data.inotify_pcapng_is_running == 1)
		return 0;

	odp_global_data.inotify_pcapng_fd = -1;
	odp_global_data.inotify_watch_fd = -1;

	odp_global_data.inotify_pcapng_fd = inotify_init();
	if (odp_global_data.inotify_pcapng_fd == -1) {
		ODP_ERR("can't init inotify. pcap disabled\n");
		goto out_destroy;
	}

	odp_global_data.inotify_watch_fd =
		inotify_add_watch(odp_global_data.inotify_pcapng_fd,
				  PCAPNG_WATCH_DIR, IN_CLOSE | IN_OPEN);

	if (odp_global_data.inotify_watch_fd == -1) {
		ODP_ERR("can't register inotify for %s. pcap disabled\n",
			strerror(errno));
		goto out_destroy;
	}

	/* create a thread to poll inotify triggers */
	pthread_attr_init(&attr);
	ret = pthread_create(&odp_global_data.inotify_thread, &attr,
			     inotify_update, entry);
	if (ret)
		ODP_ERR("can't start inotify thread. pcap disabled\n");
	else
		odp_global_data.inotify_pcapng_is_running = 1;

	return ret;

out_destroy:
	pcapng_destroy(entry);

	return ret;
}

void pcapng_destroy(pktio_entry_t *entry)
{
	int ret;
	unsigned int i;
	unsigned int max_queue =
		MAX(entry->s.num_in_queue, entry->s.num_out_queue);

	if (odp_global_data.inotify_pcapng_is_running == 1) {
		ret = pthread_cancel(odp_global_data.inotify_thread);
		if (ret)
			ODP_ERR("can't cancel inotify thread %s\n",
				strerror(errno));
	}

	/* fd's will be -1 in case of any failure */
	ret = inotify_rm_watch(odp_global_data.inotify_pcapng_fd,
			       odp_global_data.inotify_watch_fd);
	if (ret)
		ODP_ERR("can't deregister inotify %s\n", strerror(errno));

	if (odp_global_data.inotify_pcapng_fd != -1)
		close(odp_global_data.inotify_pcapng_fd);

	if (odp_global_data.inotify_watch_fd != -1)
		close(odp_global_data.inotify_watch_fd);

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

int write_pcapng_pkts(pktio_entry_t *entry, int qidx,
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
