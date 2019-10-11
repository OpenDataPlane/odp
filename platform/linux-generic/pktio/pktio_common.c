/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2013, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_packet_io_internal.h>
#include <errno.h>

static int sock_recv_mq_tmo_select(pktio_entry_t * const *entry,
				   const int index[],
				   unsigned num_q, unsigned *from,
				   odp_packet_t packets[], int num,
				   uint64_t usecs, fd_set *readfds,
				   int maxfd)
{
	struct timeval timeout;
	unsigned i;
	int ret;

	for (i = 0; i < num_q; i++) {
		ret = entry[i]->s.ops->recv(entry[i], index[i], packets, num);

		if (ret > 0 && from)
			*from = i;

		if (ret != 0)
			return ret;
	}

	timeout.tv_sec = usecs / (1000 * 1000);
	timeout.tv_usec = usecs - timeout.tv_sec * (1000ULL * 1000ULL);

	if (select(maxfd + 1, readfds, NULL, NULL, &timeout) == 0)
		return 0;

	for (i = 0; i < num_q; i++) {
		ret = entry[i]->s.ops->recv(entry[i], index[i], packets, num);

		if (ret > 0 && from)
			*from = i;

		if (ret != 0)
			return ret;
	}

	return 0;
}

int sock_recv_mq_tmo_try_int_driven(const struct odp_pktin_queue_t queues[],
				    unsigned num_q, unsigned *from,
				    odp_packet_t packets[], int num,
				    uint64_t usecs, int *trial_successful)
{
	unsigned i;
	pktio_entry_t *entry[num_q];
	int index[num_q];
	fd_set readfds;
	int maxfd = -1;
	int (*impl)(pktio_entry_t *entry[], int index[], int num_q,
		    odp_packet_t packets[], int num, unsigned *from,
		    uint64_t wait_usecs) = NULL;
	int impl_set = 0;

	/* First, we get pktio entries and queue indices. We then see if the
	   implementation function pointers are the same. If they are the
	   same, impl will be set to non-NULL; otherwise it will be NULL. */

	for (i = 0; i < num_q; i++) {
		entry[i] = get_pktio_entry(queues[i].pktio);
		index[i] = queues[i].index;
		if (entry[i] == NULL) {
			ODP_DBG("pktio entry %d does not exist\n",
				queues[i].pktio);
			*trial_successful = 0;
			return -1;
		}
		if (entry[i]->s.ops->recv_mq_tmo == NULL &&
		    entry[i]->s.ops->fd_set == NULL) {
			*trial_successful = 0;
			return 0;
		}
		if (!impl_set) {
			impl = entry[i]->s.ops->recv_mq_tmo;
			impl_set = 1;
		} else {
			if (impl != entry[i]->s.ops->recv_mq_tmo)
				impl = NULL;
		}
	}

	/* Check whether we can call the compatible implementation */
	if (impl != NULL) {
		*trial_successful = 1;
		return impl(entry, index, num_q, packets, num, from, usecs);
	}

	/* Get file descriptor sets of devices. maxfd will be -1 if this
	   fails. */
	FD_ZERO(&readfds);
	for (i = 0; i < num_q; i++) {
		if (entry[i]->s.ops->fd_set) {
			int maxfd2;

			maxfd2 = entry[i]->s.ops->fd_set(
				entry[i], queues[i].index, &readfds);
			if (maxfd2 < 0) {
				maxfd = -1;
				break;
			}
			if (maxfd2 > maxfd)
				maxfd = maxfd2;
		} else {
			maxfd = -1;
		}
	}

	/* Check whether we can call the select() implementation */
	if (maxfd >= 0) {
		*trial_successful = 1;
		return sock_recv_mq_tmo_select(entry, index, num_q, from,
					       packets, num, usecs,
					       &readfds, maxfd);
	}

	/* No mechanism worked. Set trial_successful to 0 so that polling will
	   be used by the main implementation. */
	*trial_successful = 0;
	return 0;
}
