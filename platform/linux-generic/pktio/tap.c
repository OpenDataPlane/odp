/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015 Ilya Maximets <i.maximets@samsung.com>
 * Copyright (c) 2021-2023 Nokia
 */

/**
 * @file
 *
 * TAP pktio type
 *
 * This file provides a pktio interface that allows for creating and
 * send/receive packets through TAP interface. It is intended for use
 * as a simple conventional communication method between applications
 * that use kernel network stack (ping, ssh, iperf, etc.) and ODP
 * applications for the purpose of functional testing.
 *
 * To use this interface the name passed to odp_pktio_open() must begin
 * with "tap:" and be in the format:
 *
 * tap:iface
 *
 *   iface   the name of TAP device to be created.
 *
 * TUN/TAP kernel module should be loaded to use this pktio.
 * There should be no device named 'iface' in the system.
 * The total length of the 'iface' is limited by IF_NAMESIZE.
 */

#include <odp_posix_extensions.h>

#include <odp/api/debug.h>
#include <odp/api/hints.h>
#include <odp/api/packet_io.h>
#include <odp/api/random.h>
#include <odp/api/ticketlock.h>

#include <odp/api/plat/packet_inlines.h>

#include <odp_parse_internal.h>
#include <odp_debug_internal.h>
#include <odp_socket_common.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_classification_internal.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_tun.h>

typedef struct {
	int fd;				/**< file descriptor for tap interface*/
	int skfd;			/**< socket descriptor */
	uint32_t mtu;			/**< cached mtu */
	uint32_t mtu_max;		/**< maximum supported MTU value */
	unsigned char if_mac[ETH_ALEN];	/**< MAC address of pktio side (not a
					     MAC address of kernel interface)*/
	odp_pool_t pool;		/**< pool to alloc packets from */
} pkt_tap_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_tap_t),
		  "PKTIO_PRIVATE_SIZE too small");

static inline pkt_tap_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_tap_t *)(uintptr_t)(pktio_entry->pkt_priv);
}

static int gen_random_mac(unsigned char *mac)
{
	mac[0] = 0x7a; /* not multicast and local assignment bit is set */
	if (odp_random_data(mac + 1, 5, ODP_RANDOM_BASIC) < 5) {
		_ODP_ERR("odp_random_data failed.\n");
		return -1;
	}
	return 0;
}

static int mac_addr_set_fd(int fd, const char *name,
			   const unsigned char mac_dst[])
{
	struct ifreq ethreq;
	int ret;

	memset(&ethreq, 0, sizeof(ethreq));
	snprintf(ethreq.ifr_name, IF_NAMESIZE, "%s", name);

	ethreq.ifr_hwaddr.sa_family = AF_UNIX;
	memcpy(ethreq.ifr_hwaddr.sa_data, mac_dst, ETH_ALEN);

	ret = ioctl(fd, SIOCSIFHWADDR, &ethreq);
	if (ret != 0) {
		_ODP_ERR("ioctl(SIOCSIFHWADDR): %s: \"%s\".\n", strerror(errno), ethreq.ifr_name);
		return -1;
	}

	return 0;
}

static int tap_pktio_open(odp_pktio_t id ODP_UNUSED,
			  pktio_entry_t *pktio_entry,
			  const char *devname, odp_pool_t pool)
{
	int fd, skfd, flags;
	uint32_t mtu;
	struct ifreq ifr;
	pkt_tap_t *tap = pkt_priv(pktio_entry);

	if (strncmp(devname, "tap:", 4) != 0)
		return -1;

	/* Init pktio entry */
	memset(tap, 0, sizeof(*tap));
	tap->fd = -1;
	tap->skfd = -1;

	if (pool == ODP_POOL_INVALID)
		return -1;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		_ODP_ERR("failed to open /dev/net/tun: %s\n", strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *        IFF_TAP   - TAP device
	 *
	 *        IFF_NO_PI - Do not provide packet information
	 */
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", devname + 4);

	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
		_ODP_ERR("%s: creating tap device failed: %s\n", ifr.ifr_name, strerror(errno));
		goto tap_err;
	}

	/* Set nonblocking mode on interface. */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		_ODP_ERR("fcntl(F_GETFL) failed: %s\n", strerror(errno));
		goto tap_err;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		_ODP_ERR("fcntl(F_SETFL) failed: %s\n", strerror(errno));
		goto tap_err;
	}

	if (gen_random_mac(tap->if_mac) < 0)
		goto tap_err;

	/* Create AF_INET socket for network interface related operations. */
	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0) {
		_ODP_ERR("socket creation failed: %s\n", strerror(errno));
		goto tap_err;
	}

	mtu = _odp_mtu_get_fd(skfd, devname + 4);
	if (mtu == 0) {
		_ODP_ERR("_odp_mtu_get_fd failed: %s\n", strerror(errno));
		goto sock_err;
	}
	tap->mtu_max = _ODP_SOCKET_MTU_MAX;
	if (mtu > tap->mtu_max)
		tap->mtu_max =  mtu;

	tap->fd = fd;
	tap->skfd = skfd;
	tap->mtu = mtu;
	tap->pool = pool;
	return 0;
sock_err:
	close(skfd);
tap_err:
	close(fd);
	_ODP_ERR("Tap device alloc failed.\n");
	return -1;
}

static int tap_pktio_start(pktio_entry_t *pktio_entry)
{
	struct ifreq ifr;
	pkt_tap_t *tap = pkt_priv(pktio_entry);

	odp_memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s",
		 (char *)pktio_entry->name + 4);

		/* Up interface by default. */
	if (ioctl(tap->skfd, SIOCGIFFLAGS, &ifr) < 0) {
		_ODP_ERR("ioctl(SIOCGIFFLAGS) failed: %s\n", strerror(errno));
		goto sock_err;
	}

	ifr.ifr_flags |= IFF_UP;
	ifr.ifr_flags |= IFF_RUNNING;

	if (ioctl(tap->skfd, SIOCSIFFLAGS, &ifr) < 0) {
		_ODP_ERR("failed to come up: %s\n", strerror(errno));
		goto sock_err;
	}

	return 0;
sock_err:
	_ODP_ERR("Tap device open failed.\n");
	return -1;
}

static int tap_pktio_stop(pktio_entry_t *pktio_entry)
{
	struct ifreq ifr;
	pkt_tap_t *tap = pkt_priv(pktio_entry);

	odp_memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s",
		 (char *)pktio_entry->name + 4);

		/* Up interface by default. */
	if (ioctl(tap->skfd, SIOCGIFFLAGS, &ifr) < 0) {
		_ODP_ERR("ioctl(SIOCGIFFLAGS) failed: %s\n", strerror(errno));
		goto sock_err;
	}

	ifr.ifr_flags &= ~IFF_UP;
	ifr.ifr_flags &= ~IFF_RUNNING;

	if (ioctl(tap->skfd, SIOCSIFFLAGS, &ifr) < 0) {
		_ODP_ERR("failed to come up: %s\n", strerror(errno));
		goto sock_err;
	}

	return 0;
sock_err:
	_ODP_ERR("Tap device open failed.\n");
	return -1;
}

static int tap_pktio_close(pktio_entry_t *pktio_entry)
{
	int ret = 0;
	pkt_tap_t *tap = pkt_priv(pktio_entry);

	if (tap->fd != -1 && close(tap->fd) != 0) {
		_ODP_ERR("close(tap->fd): %s\n", strerror(errno));
		ret = -1;
	}

	if (tap->skfd != -1 && close(tap->skfd) != 0) {
		_ODP_ERR("close(tap->skfd): %s\n", strerror(errno));
		ret = -1;
	}

	return ret;
}

static odp_packet_t pack_odp_pkt(pktio_entry_t *pktio_entry, const void *data,
				 unsigned int len, odp_time_t *ts)
{
	odp_packet_t pkt;
	odp_packet_hdr_t *pkt_hdr;
	int num;
	uint16_t frame_offset = pktio_entry->pktin_frame_offset;
	const odp_proto_layer_t layer = pktio_entry->parse_layer;
	const odp_pktin_config_opt_t opt = pktio_entry->config.pktin;

	num = _odp_packet_alloc_multi(pkt_priv(pktio_entry)->pool,
				      len + frame_offset, &pkt, 1);
	if (num != 1)
		return ODP_PACKET_INVALID;

	pkt_hdr = packet_hdr(pkt);

	if (frame_offset)
		pull_head(pkt_hdr, frame_offset);

	if (odp_packet_copy_from_mem(pkt, 0, len, data) < 0) {
		_ODP_ERR("failed to copy packet data\n");
		odp_packet_free(pkt);
		return ODP_PACKET_INVALID;
	}

	if (layer) {
		if (_odp_packet_parse_common(pkt_hdr, data, len, len, layer,
					     opt) < 0) {
			odp_packet_free(pkt);
			return ODP_PACKET_INVALID;
		}

		if (pktio_cls_enabled(pktio_entry)) {
			odp_pool_t new_pool;

			if (_odp_cls_classify_packet(pktio_entry, data,
						     &new_pool, pkt_hdr)) {
				odp_packet_free(pkt);
				return ODP_PACKET_INVALID;
			}

			if (odp_unlikely(_odp_pktio_packet_to_pool(
				    &pkt, &pkt_hdr, new_pool))) {
				odp_packet_free(pkt);
				return ODP_PACKET_INVALID;
			}
		}
	}

	packet_set_ts(pkt_hdr, ts);
	pkt_hdr->input = pktio_entry->handle;

	return pkt;
}

static int tap_pktio_recv(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			  odp_packet_t pkts[], int num)
{
	pkt_tap_t *tap = pkt_priv(pktio_entry);
	ssize_t retval;
	int i;
	uint32_t mtu = tap->mtu;
	uint8_t buf[mtu];
	odp_time_t ts_val;
	odp_time_t *ts = NULL;
	int num_rx = 0;
	int num_cls = 0;
	const int cls_enabled = pktio_cls_enabled(pktio_entry);
	odp_packet_t pkt;

	odp_ticketlock_lock(&pktio_entry->rxl);

	if (pktio_entry->config.pktin.bit.ts_all ||
	    pktio_entry->config.pktin.bit.ts_ptp)
		ts = &ts_val;

	for (i = 0; i < num; i++) {
		do {
			retval = read(tap->fd, buf, mtu);
		} while (retval < 0 && errno == EINTR);

		if (ts != NULL)
			ts_val = odp_time_global();

		if (retval < 0) {
			break;
		}

		pkt = pack_odp_pkt(pktio_entry, buf, retval, ts);
		if (pkt == ODP_PACKET_INVALID)
			break;

		if (cls_enabled) {
			/* Enqueue packets directly to classifier destination queue */
			pkts[num_cls++] = pkt;
			num_cls = _odp_cls_enq(pkts, num_cls, (i + 1 == num));
		} else {
			pkts[num_rx++] = pkt;
		}
	}

	/* Enqueue remaining classified packets */
	if (odp_unlikely(num_cls))
		_odp_cls_enq(pkts, num_cls, true);

	odp_ticketlock_unlock(&pktio_entry->rxl);

	return num_rx;
}

static int tap_pktio_send_lockless(pktio_entry_t *pktio_entry,
				   const odp_packet_t pkts[], int num)
{
	pkt_tap_t *tap = pkt_priv(pktio_entry);
	ssize_t retval;
	int i, n;
	uint32_t pkt_len;
	uint32_t mtu = tap->mtu;
	uint8_t tx_ts_enabled = _odp_pktio_tx_ts_enabled(pktio_entry);
	uint8_t buf[mtu];

	for (i = 0; i < num; i++) {
		pkt_len = odp_packet_len(pkts[i]);

		if (odp_unlikely(pkt_len > mtu)) {
			if (i == 0) {
				return -1;
			}
			break;
		}

		if (odp_packet_copy_to_mem(pkts[i], 0, pkt_len, buf) < 0) {
			_ODP_ERR("failed to copy packet data\n");
			break;
		}

		do {
			retval = write(tap->fd, buf, pkt_len);
		} while (retval < 0 && errno == EINTR);

		if (retval < 0) {
			if (i == 0 && SOCK_ERR_REPORT(errno)) {
				_ODP_ERR("write(): %s\n", strerror(errno));
				return -1;
			}
			break;
		} else if ((uint32_t)retval != pkt_len) {
			_ODP_ERR("sent partial ethernet packet\n");
			if (i == 0) {
				return -1;
			}
			break;
		}

		if (tx_ts_enabled) {
			if (odp_unlikely(packet_hdr(pkts[i])->p.flags.ts_set))
				_odp_pktio_tx_ts_set(pktio_entry);
		}
	}

	for (n = 0; n < i; n++)
		odp_packet_free(pkts[n]);

	return i;
}

static int tap_pktio_send(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			  const odp_packet_t pkts[], int num)
{
	int ret;

	odp_ticketlock_lock(&pktio_entry->txl);

	ret = tap_pktio_send_lockless(pktio_entry, pkts, num);

	odp_ticketlock_unlock(&pktio_entry->txl);

	return ret;
}

static uint32_t tap_mtu_get(pktio_entry_t *pktio_entry)
{
	uint32_t ret;

	ret =  _odp_mtu_get_fd(pkt_priv(pktio_entry)->skfd,
			       pktio_entry->name + 4);
	if (ret > 0)
		pkt_priv(pktio_entry)->mtu = ret;

	return ret;
}

static int tap_mtu_set(pktio_entry_t *pktio_entry, uint32_t maxlen_input,
		       uint32_t maxlen_output ODP_UNUSED)
{
	pkt_tap_t *tap = pkt_priv(pktio_entry);
	int ret;

	ret = _odp_mtu_set_fd(tap->skfd, pktio_entry->name + 4, maxlen_input);
	if (ret)
		return ret;

	tap->mtu = maxlen_input;

	return 0;
}

static int tap_promisc_mode_set(pktio_entry_t *pktio_entry,
				odp_bool_t enable)
{
	return _odp_promisc_mode_set_fd(pkt_priv(pktio_entry)->skfd,
					pktio_entry->name + 4, enable);
}

static int tap_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	return _odp_promisc_mode_get_fd(pkt_priv(pktio_entry)->skfd,
					pktio_entry->name + 4);
}

static int tap_mac_addr_get(pktio_entry_t *pktio_entry, void *mac_addr)
{
	memcpy(mac_addr, pkt_priv(pktio_entry)->if_mac, ETH_ALEN);
	return ETH_ALEN;
}

static int tap_mac_addr_set(pktio_entry_t *pktio_entry, const void *mac_addr)
{
	pkt_tap_t *tap = pkt_priv(pktio_entry);

	memcpy(tap->if_mac, mac_addr, ETH_ALEN);

	return mac_addr_set_fd(tap->fd, (char *)pktio_entry->name + 4,
			  tap->if_mac);
}

static int tap_link_status(pktio_entry_t *pktio_entry)
{
	return _odp_link_status_fd(pkt_priv(pktio_entry)->skfd,
				   pktio_entry->name + 4);
}

static int tap_link_info(pktio_entry_t *pktio_entry, odp_pktio_link_info_t *info)
{
	return _odp_link_info_fd(pkt_priv(pktio_entry)->skfd, pktio_entry->name + 4, info);
}

static int tap_capability(pktio_entry_t *pktio_entry ODP_UNUSED,
			  odp_pktio_capability_t *capa)
{
	pkt_tap_t *tap = pkt_priv(pktio_entry);

	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues  = 1;
	capa->max_output_queues = 1;
	capa->set_op.op.promisc_mode = 1;
	capa->set_op.op.mac_addr = 1;
	capa->set_op.op.maxlen = 1;

	capa->maxlen.equal = true;
	capa->maxlen.min_input = _ODP_SOCKET_MTU_MIN;
	capa->maxlen.max_input = tap->mtu_max;
	capa->maxlen.min_output = _ODP_SOCKET_MTU_MIN;
	capa->maxlen.max_output = tap->mtu_max;

	odp_pktio_config_init(&capa->config);
	capa->config.pktin.bit.ts_all = 1;
	capa->config.pktin.bit.ts_ptp = 1;

	capa->config.pktout.bit.ts_ena = 1;

	capa->tx_compl.mode_event = 1;
	capa->tx_compl.mode_poll = 1;

	return 0;
}

const pktio_if_ops_t _odp_tap_pktio_ops = {
	.name = "tap",
	.print = NULL,
	.init_global = NULL,
	.init_local = NULL,
	.term = NULL,
	.open = tap_pktio_open,
	.close = tap_pktio_close,
	.start = tap_pktio_start,
	.stop = tap_pktio_stop,
	.recv = tap_pktio_recv,
	.send = tap_pktio_send,
	.maxlen_get = tap_mtu_get,
	.maxlen_set = tap_mtu_set,
	.promisc_mode_set = tap_promisc_mode_set,
	.promisc_mode_get = tap_promisc_mode_get,
	.mac_get = tap_mac_addr_get,
	.mac_set = tap_mac_addr_set,
	.link_status = tap_link_status,
	.link_info = tap_link_info,
	.capability = tap_capability,
	.pktio_ts_res = NULL,
	.pktio_ts_from_ns = NULL,
	.pktio_time = NULL,
	.config = NULL
};
