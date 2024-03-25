/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Nokia
 */

/**
 * @example odp_packet_gen.c
 *
 * Performance optimized packet generator application
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

/* enable usleep */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#if ODP_THREAD_COUNT_MAX > 33
/* One control thread, even number of workers */
#define MAX_THREADS  33
#else
#define MAX_THREADS  ODP_THREAD_COUNT_MAX
#endif

#define MAX_WORKERS  (MAX_THREADS - 1)

/* At least one control and one worker thread */
ODP_STATIC_ASSERT(MAX_WORKERS >= 1, "Too few threads");

/* Maximum number of packet IO interfaces */
#define MAX_PKTIOS        16
/* Maximum number of packets to be allocated for
 * one transmit round: bursts * burst_size * bins */
#define MAX_ALLOC_PACKETS (64 * 1024)
/* Maximum number of packet length bins */
#define MAX_BINS          1024
#define MAX_PKTIO_NAME    255
#define RX_THREAD         1
#define TX_THREAD         2
#define MAX_VLANS         4
/* Number of random 16-bit words used to generate random length packets */
#define RAND_16BIT_WORDS  128
/* Max retries to generate random data */
#define MAX_RAND_RETRIES  1000

/* Use don't free */
#define TX_MODE_DF        0
/* Use static references */
#define TX_MODE_REF       1
/* Use packet copy */
#define TX_MODE_COPY      2

/* Minimum number of packets to receive in CI test */
#define MIN_RX_PACKETS_CI 800

/* Identifier for payload-timestamped packets */
#define TS_MAGIC 0xff88ee99ddaaccbb

enum {
	L4_PROTO_UDP = 0,
	L4_PROTO_TCP
};

ODP_STATIC_ASSERT(MAX_PKTIOS <= UINT8_MAX, "Interface index must fit into uint8_t\n");

typedef struct test_options_t {
	uint64_t gap_nsec;
	uint64_t quit;
	uint64_t update_msec;
	uint32_t num_rx;
	uint32_t num_tx;
	uint32_t num_cpu;
	uint32_t num_pktio;
	uint32_t num_pkt;
	uint32_t pkt_len;
	uint8_t  use_rand_pkt_len;
	uint8_t  direct_rx;
	uint32_t rand_pkt_len_min;
	uint32_t rand_pkt_len_max;
	uint32_t rand_pkt_len_bins;
	uint32_t hdr_len;
	uint32_t burst_size;
	uint32_t bursts;
	uint32_t num_vlan;
	uint32_t ipv4_src;
	uint32_t ipv4_dst;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t wait_sec;
	uint32_t wait_start_sec;
	uint32_t mtu;
	uint8_t l4_proto;
	int tx_mode;
	odp_bool_t promisc_mode;
	odp_bool_t calc_latency;
	odp_bool_t calc_cs;
	odp_bool_t fill_pl;

	struct vlan_hdr {
		uint16_t tpid;
		uint16_t tci;
	} vlan[MAX_VLANS];

	struct {
		uint32_t src_port;
		uint32_t dst_port;
	} c_mode;

	char     pktio_name[MAX_PKTIOS][MAX_PKTIO_NAME + 1];
	char     ipv4_src_s[24];
	char     ipv4_dst_s[24];

} test_options_t;

typedef struct thread_arg_t {
	void *global;
	int tx_thr;

	/* pktout queue per pktio interface (per thread) */
	odp_pktout_queue_t pktout[MAX_PKTIOS];

	/* In direct_rx mode, pktin queue per pktio interface (per thread) */
	odp_pktin_queue_t pktin[MAX_PKTIOS];

	/* Pre-built packets for TX thread */
	odp_packet_t packet[MAX_PKTIOS][MAX_ALLOC_PACKETS];

} thread_arg_t;

typedef struct ODP_ALIGNED_CACHE thread_stat_t {
	uint64_t time_nsec;
	uint64_t rx_timeouts;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t rx_lat_nsec;
	uint64_t rx_lat_min_nsec;
	uint64_t rx_lat_max_nsec;
	uint64_t rx_lat_packets;

	uint64_t tx_timeouts;
	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t tx_drops;

	int      thread_type;

	struct {
		uint64_t rx_packets;
		uint64_t tx_packets;

	} pktio[MAX_PKTIOS];

} thread_stat_t;

typedef struct test_global_t {
	test_options_t test_options;
	odp_atomic_u32_t exit_test;
	odp_barrier_t barrier;
	odp_cpumask_t cpumask;
	odp_pool_t pool;
	uint64_t drained;
	odph_thread_t thread_tbl[MAX_THREADS];
	thread_stat_t stat[MAX_THREADS];
	thread_arg_t thread_arg[MAX_THREADS];

	struct {
		odph_ethaddr_t eth_src;
		odph_ethaddr_t eth_dst;
		odp_pktio_t pktio;
		odp_pktout_queue_t pktout[MAX_THREADS];
		odp_pktin_queue_t pktin[MAX_THREADS];
		int started;

	} pktio[MAX_PKTIOS];

	/* Interface lookup table. Table index is pktio_index of the API. */
	uint8_t if_from_pktio_idx[ODP_PKTIO_MAX_INDEX + 1];

	uint32_t num_tx_pkt;
	uint32_t num_bins;
	uint32_t len_bin[MAX_BINS];

} test_global_t;

typedef struct ODP_PACKED {
	uint64_t magic;
	uint64_t tx_ts;
} ts_data_t;

typedef struct {
	uint64_t nsec;
	uint64_t min;
	uint64_t max;
	uint64_t packets;
} rx_lat_data_t;

static test_global_t *test_global;

static void print_usage(void)
{
	printf("\n"
	       "ODP packet generator\n"
	       "\n"
	       "Usage: odp_packet_gen [options]\n"
	       "\n"
	       "  Mandatory:\n"
	       "  -i, --interface <name>  Packet IO interfaces. Comma-separated list of\n"
	       "                          interface names (no spaces) e.g. eth0,eth1.\n"
	       "                          At least one interface is required.\n"
	       "\n");
	printf("  Optional:\n"
	       "  -e, --eth_dst <mac>       Destination MAC address. Comma-separated list of\n"
	       "                            addresses (no spaces), one address per packet IO\n"
	       "                            interface e.g. AA:BB:CC:DD:EE:FF,11:22:33:44:55:66\n"
	       "                            Default per interface: 02:00:00:A0:B0:CX, where X = 0,1,...\n"
	       "  -v, --vlan <tpid:tci>     VLAN configuration. Comma-separated list of VLAN TPID:TCI\n"
	       "                            values in hexadecimal, starting from the outer most VLAN.\n"
	       "                            For example:\n"
	       "                            VLAN 200 (decimal):          8100:c8\n"
	       "                            Double tagged VLANs 1 and 2: 88a8:1,8100:2\n"
	       "  -r, --num_rx              Number of receive threads. Default: 1\n"
	       "  -t, --num_tx              Number of transmit threads. Default: 1\n"
	       "  -n, --num_pkt             Number of packets in the pool. Default: 1000\n"
	       "  -l, --len                 Packet length. Default: 512\n"
	       "  -L, --len_range <min,max,bins>\n"
	       "                            Random packet length. Specify the minimum and maximum\n"
	       "                            packet lengths and the number of bins. To reduce pool size\n"
	       "                            requirement the length range can be divided into even sized\n"
	       "                            bins (max %u). Min and max size packets are always used and included\n"
	       "                            into the number of bins (bins >= 2). Bin value of 0 means\n"
	       "                            that each packet length is used. Comma-separated (no spaces).\n"
	       "                            Overrides standard packet length option.\n"
	       "  -D, --direct_rx           Direct input mode (default: 0)\n"
	       "                              0: Use scheduler for packet input\n"
	       "                              1: Poll packet input in direct mode\n", MAX_BINS);
	printf("  -m, --tx_mode             Transmit mode (default 1):\n"
	       "                              0: Re-send packets with don't free option\n"
	       "                              1: Send static packet references. Some features may\n"
	       "                                 not be available with references.\n"
	       "                              2: Send copies of packets\n"
	       "  -M, --mtu <len>           Interface MTU in bytes.\n"
	       "  -b, --burst_size          Transmit burst size. Default: 8\n"
	       "  -x, --bursts              Number of bursts per one transmit round. Default: 1\n"
	       "  -g, --gap                 Gap between transmit rounds in nsec. Default: 1000000\n"
	       "                            Transmit packet rate per interface:\n"
	       "                              num_tx * burst_size * bursts * (10^9 / gap)\n"
	       "  -s, --ipv4_src            IPv4 source address. Default: 192.168.0.1\n"
	       "  -d, --ipv4_dst            IPv4 destination address. Default: 192.168.0.2\n"
	       "  -o, --src_port            UDP/TCP source port. Default: 10000\n"
	       "  -p, --dst_port            UDP/TCP destination port. Default: 20000\n"
	       "  -N, --proto               L4 protocol. Default: 0\n"
	       "                              0: UDP\n"
	       "                              1: TCP\n"
	       "  -P, --promisc_mode        Enable promiscuous mode.\n"
	       "  -a, --latency             Calculate latency. Cannot be used with packet\n"
	       "                            references (see \"--tx_mode\").\n"
	       "  -c, --c_mode <counts>     Counter mode for incrementing UDP/TCP port numbers.\n"
	       "                            Specify the number of port numbers used starting from\n"
	       "                            src_port/dst_port. Comma-separated (no spaces) list of\n"
	       "                            count values: <src_port count>,<dst_port count>\n"
	       "                            Default value: 0,0\n"
	       "  -C, --no_udp_checksum     Do not calculate UDP checksum. Instead, set it to\n"
	       "                            zero in every packet.\n"
	       "  -A, --no_payload_fill     Do not fill payload. By default, payload is filled\n"
	       "                            with a pattern until the end of first packet\n"
	       "                            segment.\n"
	       "  -q, --quit                Quit after this many transmit rounds.\n"
	       "                            Default: 0 (don't quit)\n"
	       "  -u, --update_stat <msec>  Update and print statistics every <msec> milliseconds.\n"
	       "                            0: Don't print statistics periodically (default)\n"
	       "  -h, --help                This help\n"
	       "  -w, --wait <sec>          Wait up to <sec> seconds for network links to be up.\n"
	       "                            Default: 0 (don't check link status)\n"
	       "  -W, --wait_start <sec>    Wait <sec> seconds before starting traffic. Default: 0\n"
	       "\n");
}

static int parse_vlan(const char *str, test_global_t *global)
{
	struct vlan_hdr *vlan;
	const char *start = str;
	char *end;
	int num_vlan = 0;
	intptr_t str_len = strlen(str);

	while (num_vlan < MAX_VLANS) {
		vlan = &global->test_options.vlan[num_vlan];

		/* TPID in hexadecimal */
		end = NULL;
		vlan->tpid = strtoul(start, &end, 16);
		if (end < start)
			break;

		/* Skip ':' */
		start = end + 1;
		if (start - str >= str_len)
			break;

		/* TCI in hexadecimal */
		end = NULL;
		vlan->tci = strtoul(start, &end, 16);
		if (end < start)
			break;

		num_vlan++;

		/* Skip ',' or stop at the string end */
		start = end + 1;
		if (start - str >= str_len)
			break;
	}

	return num_vlan;
}

static int init_bins(test_global_t *global)
{
	uint32_t i, bin_size;
	test_options_t *test_options = &global->test_options;
	uint32_t num_bins = test_options->rand_pkt_len_bins;
	uint32_t len_min = test_options->rand_pkt_len_min;
	uint32_t len_max = test_options->rand_pkt_len_max;
	uint32_t num_bytes = len_max - len_min + 1;

	if (len_max <= len_min) {
		ODPH_ERR("Error: Bad max packet length\n");
		return -1;
	}

	if (num_bins == 0)
		num_bins = num_bytes;

	if (num_bins == 1 || num_bins > MAX_BINS || num_bins > num_bytes) {
		ODPH_ERR("Error: Bad number of packet length bins: %u\n", num_bins);
		return -1;
	}

	bin_size = (len_max - len_min + 1) / (num_bins - 1);

	/* Min length is the first bin */
	for (i = 0; i < num_bins - 1; i++)
		global->len_bin[i] = len_min + (i * bin_size);

	/* Max length is the last bin */
	global->len_bin[i] = len_max;
	global->num_bins   = num_bins;

	return 0;
}

static int parse_options(int argc, char *argv[], test_global_t *global)
{
	int opt, i, len, str_len, long_index, port;
	unsigned long int count;
	uint32_t min_packets, num_tx_pkt, num_tx_alloc, pkt_len, val, bins;
	char *name, *str, *end;
	test_options_t *test_options = &global->test_options;
	int ret = 0;
	uint8_t default_eth_dst[6] = {0x02, 0x00, 0x00, 0xa0, 0xb0, 0xc0};

	static const struct option longopts[] = {
		{"interface",   required_argument, NULL, 'i'},
		{"eth_dst",     required_argument, NULL, 'e'},
		{"num_rx",      required_argument, NULL, 'r'},
		{"num_tx",      required_argument, NULL, 't'},
		{"num_pkt",     required_argument, NULL, 'n'},
		{"proto",       required_argument, NULL, 'N'},
		{"len",         required_argument, NULL, 'l'},
		{"len_range",   required_argument, NULL, 'L'},
		{"direct_rx",   required_argument, NULL, 'D'},
		{"tx_mode",     required_argument, NULL, 'm'},
		{"burst_size",  required_argument, NULL, 'b'},
		{"bursts",      required_argument, NULL, 'x'},
		{"gap",         required_argument, NULL, 'g'},
		{"vlan",        required_argument, NULL, 'v'},
		{"ipv4_src",    required_argument, NULL, 's'},
		{"ipv4_dst",    required_argument, NULL, 'd'},
		{"src_port",    required_argument, NULL, 'o'},
		{"dst_port",    required_argument, NULL, 'p'},
		{"promisc_mode", no_argument,      NULL, 'P'},
		{"latency",     no_argument,       NULL, 'a'},
		{"c_mode",      required_argument, NULL, 'c'},
		{"no_udp_checksum", no_argument,   NULL, 'C'},
		{"no_payload_fill", no_argument,   NULL, 'A'},
		{"mtu",         required_argument, NULL, 'M'},
		{"quit",        required_argument, NULL, 'q'},
		{"wait",        required_argument, NULL, 'w'},
		{"wait_start",  required_argument, NULL, 'W'},
		{"update_stat", required_argument, NULL, 'u'},
		{"help",        no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+i:e:r:t:n:N:l:L:D:m:M:b:x:g:v:s:d:o:p:c:CAq:u:w:W:Pah";

	test_options->num_pktio  = 0;
	test_options->num_rx     = 1;
	test_options->num_tx     = 1;
	test_options->num_pkt    = 1000;
	test_options->pkt_len    = 512;
	test_options->use_rand_pkt_len = 0;
	test_options->direct_rx  = 0;
	test_options->tx_mode    = TX_MODE_REF;
	test_options->burst_size = 8;
	test_options->bursts     = 1;
	test_options->gap_nsec   = 1000000;
	test_options->num_vlan   = 0;
	test_options->promisc_mode = 0;
	test_options->calc_latency = 0;
	test_options->calc_cs    = 1;
	test_options->fill_pl    = 1;
	strncpy(test_options->ipv4_src_s, "192.168.0.1",
		sizeof(test_options->ipv4_src_s) - 1);
	strncpy(test_options->ipv4_dst_s, "192.168.0.2",
		sizeof(test_options->ipv4_dst_s) - 1);
	if (odph_ipv4_addr_parse(&test_options->ipv4_src, test_options->ipv4_src_s)) {
		ODPH_ERR("Address parse failed\n");
		return -1;
	}
	if (odph_ipv4_addr_parse(&test_options->ipv4_dst, test_options->ipv4_dst_s)) {
		ODPH_ERR("Address parse failed\n");
		return -1;
	}
	test_options->src_port = 10000;
	test_options->dst_port = 20000;
	test_options->c_mode.src_port = 0;
	test_options->c_mode.dst_port = 0;
	test_options->quit = 0;
	test_options->update_msec = 0;
	test_options->wait_sec = 0;
	test_options->wait_start_sec = 0;
	test_options->mtu = 0;
	test_options->l4_proto = L4_PROTO_UDP;

	for (i = 0; i < MAX_PKTIOS; i++) {
		memcpy(global->pktio[i].eth_dst.addr, default_eth_dst, 6);
		global->pktio[i].eth_dst.addr[5] += i;
	}

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'i':
			i = 0;
			str = optarg;
			str_len = strlen(str);

			while (str_len > 0) {
				len = strcspn(str, ",");
				str_len -= len + 1;

				if (i == MAX_PKTIOS) {
					ODPH_ERR("Error: Too many interfaces\n");
					ret = -1;
					break;
				}

				if (len > MAX_PKTIO_NAME) {
					ODPH_ERR("Error: Too long interface name %s\n", str);
					ret = -1;
					break;
				}

				name = test_options->pktio_name[i];
				memcpy(name, str, len);
				str += len + 1;
				i++;
			}

			test_options->num_pktio = i;

			break;
		case 'e':
			i = 0;
			str = optarg;
			str_len = strlen(str);

			while (str_len > 0) {
				odph_ethaddr_t *dst = &global->pktio[i].eth_dst;

				len = strcspn(str, ",");
				str_len -= len + 1;

				if (i == MAX_PKTIOS) {
					ODPH_ERR("Error: Too many MAC addresses\n");
					ret = -1;
					break;
				}

				if (odph_eth_addr_parse(dst, str)) {
					ODPH_ERR("Error: Bad MAC address: %s\n", str);
					ret = -1;
					break;
				}

				str += len + 1;
				i++;
			}
			break;
		case 'o':
			port = atoi(optarg);
			if (port < 0 || port > UINT16_MAX) {
				ODPH_ERR("Error: Bad source port: %d\n", port);
				ret = -1;
				break;
			}
			test_options->src_port = port;
			break;
		case 'p':
			port = atoi(optarg);
			if (port < 0 || port > UINT16_MAX) {
				ODPH_ERR("Error: Bad destination port: %d\n", port);
				ret = -1;
				break;
			}
			test_options->dst_port = port;
			break;
		case 'P':
			test_options->promisc_mode = 1;
			break;
		case 'a':
			test_options->calc_latency = 1;
			break;
		case 'r':
			test_options->num_rx = atoi(optarg);
			break;
		case 't':
			test_options->num_tx = atoi(optarg);
			break;
		case 'n':
			test_options->num_pkt = atoi(optarg);
			break;
		case 'N':
			test_options->l4_proto = atoi(optarg);
			break;
		case 'l':
			test_options->pkt_len = atoi(optarg);
			break;
		case 'L':
			pkt_len = strtoul(optarg, &end, 0);
			test_options->rand_pkt_len_min = pkt_len;
			end++;
			pkt_len = strtoul(end, &str, 0);
			test_options->rand_pkt_len_max = pkt_len;
			str++;
			val = strtoul(str, NULL, 0);
			test_options->rand_pkt_len_bins = val;
			test_options->use_rand_pkt_len = 1;
			break;
		case 'D':
			test_options->direct_rx = atoi(optarg);
			break;
		case 'm':
			test_options->tx_mode = atoi(optarg);
			break;
		case 'M':
			test_options->mtu = atoi(optarg);
			break;
		case 'b':
			test_options->burst_size = atoi(optarg);
			break;
		case 'x':
			test_options->bursts = atoi(optarg);
			break;
		case 'g':
			test_options->gap_nsec = atoll(optarg);
			break;
		case 'v':
			test_options->num_vlan = parse_vlan(optarg, global);
			if (test_options->num_vlan == 0) {
				ODPH_ERR("Error: Did not find any VLANs\n");
				ret = -1;
			}
			break;
		case 's':
			if (odph_ipv4_addr_parse(&test_options->ipv4_src,
						 optarg)) {
				ODPH_ERR("Error: Bad IPv4 source address: %s\n", optarg);
				ret = -1;
			}
			strncpy(test_options->ipv4_src_s, optarg,
				sizeof(test_options->ipv4_src_s) - 1);
			break;
		case 'd':
			if (odph_ipv4_addr_parse(&test_options->ipv4_dst,
						 optarg)) {
				ODPH_ERR("Error: Bad IPv4 destination address: %s\n", optarg);
				ret = -1;
			}
			strncpy(test_options->ipv4_dst_s, optarg,
				sizeof(test_options->ipv4_dst_s) - 1);
			break;
		case 'c':
			count = strtoul(optarg, &end, 0);
			test_options->c_mode.src_port = count;

			end++;
			count = strtoul(end, NULL, 0);
			test_options->c_mode.dst_port = count;
			break;
		case 'C':
			test_options->calc_cs = 0;
			break;
		case 'A':
			test_options->fill_pl = 0;
			break;
		case 'q':
			test_options->quit = atoll(optarg);
			break;
		case 'u':
			test_options->update_msec = atoll(optarg);
			break;
		case 'w':
			test_options->wait_sec = atoi(optarg);
			break;
		case 'W':
			test_options->wait_start_sec = atoi(optarg);
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (ret)
		return -1;

	if (test_options->num_pktio == 0) {
		ODPH_ERR("Error: At least one packet IO interface is needed.\n");
		ODPH_ERR("       Use -i <name> to specify interfaces.\n");
		return -1;
	}

	if (test_options->num_rx < 1 && test_options->num_tx < 1) {
		ODPH_ERR("Error: At least one rx or tx thread needed.\n");
		return -1;
	}

	test_options->num_cpu = test_options->num_rx + test_options->num_tx;

	if (test_options->num_cpu > MAX_WORKERS) {
		ODPH_ERR("Error: Too many worker threads\n");
		return -1;
	}

	num_tx_pkt = test_options->burst_size * test_options->bursts;
	global->num_tx_pkt = num_tx_pkt;

	if (num_tx_pkt == 0) {
		ODPH_ERR("Error: Bad number of tx packets: %u\n", num_tx_pkt);
		return -1;
	}

	if (test_options->use_rand_pkt_len) {
		if (init_bins(global))
			return -1;
	}

	bins = global->num_bins ? global->num_bins : 1;
	num_tx_alloc = num_tx_pkt * bins;
	if (num_tx_alloc > MAX_ALLOC_PACKETS) {
		ODPH_ERR("Error: Too many tx packets: %u\n", num_tx_alloc);
		return -1;
	}

	/* Pool needs to have enough packets for all TX side pre-allocated packets and
	 * a burst per thread (for packet copies). RX side needs one burst per thread per pktio. */
	min_packets  = test_options->num_pktio * test_options->num_tx * num_tx_alloc;
	min_packets += test_options->num_tx * test_options->burst_size;
	min_packets += test_options->num_pktio * test_options->num_rx * test_options->burst_size;

	if (test_options->num_pkt < min_packets) {
		ODPH_ERR("Error: Pool needs to have at least %u packets\n", min_packets);
		return -1;
	}

	if (test_options->calc_latency && test_options->tx_mode == TX_MODE_REF) {
		ODPH_ERR("Error: Latency test is not supported with packet references (--tx_mode 1)\n");
		return -1;
	}
	if (test_options->calc_latency && (test_options->num_rx < 1 || test_options->num_tx < 1)) {
		ODPH_ERR("Error: Latency test requires both rx and tx threads\n");
		return -1;
	}

	if (test_options->gap_nsec) {
		double gap_hz = 1000000000.0 / test_options->gap_nsec;

		if (gap_hz > (double)odp_time_local_res()) {
			ODPH_ERR("\nWARNING: Burst gap exceeds time counter resolution "
				 "%" PRIu64 "\n\n", odp_time_local_res());
		}
	}

	if (global->num_bins) {
		if (num_tx_pkt > global->num_bins && num_tx_pkt % global->num_bins)
			ODPH_ERR("\nWARNING: Transmit packet count is not evenly divisible into packet length bins.\n\n");

		if (num_tx_pkt < global->num_bins)
			ODPH_ERR("\nWARNING: Not enough packets for every packet length bin.\n\n");
	}

	if (test_options->c_mode.dst_port && num_tx_pkt % test_options->c_mode.dst_port)
		ODPH_ERR("\nWARNING: Transmit packet count is not evenly divisible by destination port count.\n\n");

	if (test_options->c_mode.src_port && num_tx_pkt % test_options->c_mode.src_port)
		ODPH_ERR("\nWARNING: Transmit packet count is not evenly divisible by source port count.\n\n");

	if (test_options->l4_proto != L4_PROTO_TCP && test_options->l4_proto != L4_PROTO_UDP) {
		ODPH_ERR("Error: Invalid L4 protocol: %" PRIu8 "\n", test_options->l4_proto);
		return -1;
	}
	if (test_options->l4_proto == L4_PROTO_TCP && test_options->tx_mode != TX_MODE_COPY) {
		ODPH_ERR("Error: TCP protocol supported only with copy transmit mode\n");
		return -1;
	}

	test_options->hdr_len = ODPH_ETHHDR_LEN + (test_options->num_vlan * ODPH_VLANHDR_LEN) +
				ODPH_IPV4HDR_LEN;
	test_options->hdr_len += test_options->l4_proto == L4_PROTO_UDP ?
					ODPH_UDPHDR_LEN : ODPH_TCPHDR_LEN;

	pkt_len = test_options->use_rand_pkt_len ?
			test_options->rand_pkt_len_min : test_options->pkt_len;
	if (test_options->hdr_len >= pkt_len) {
		ODPH_ERR("Error: Headers do not fit into packet length %" PRIu32 "\n", pkt_len);
		return -1;
	}

	return 0;
}

static int set_num_cpu(test_global_t *global)
{
	int ret;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;

	ret = odp_cpumask_default_worker(&global->cpumask, num_cpu);

	if (ret != num_cpu) {
		int cpu;

		/* Normally we want to use only worker threads */
		if (ret > 1) {
			ODPH_ERR("Error: Too many workers. Maximum supported %i.\n", ret);
			return -1;
		}

		/* When number of workers is very limited (e.g. ODP project CI),
		 * we try to use any CPUs available. */
		ret = odp_cpumask_all_available(&global->cpumask);
		if (ret < num_cpu) {
			ODPH_ERR("Error: Not enough CPUs. Maximum supported %i.\n", ret);
			return -1;
		}

		/* Remove extra CPUs from the mask */
		cpu = odp_cpumask_first(&global->cpumask);
		while (ret > num_cpu) {
			odp_cpumask_clr(&global->cpumask, cpu);
			cpu = odp_cpumask_first(&global->cpumask);
			ret--;
		}
	}

	odp_barrier_init(&global->barrier, num_cpu + 1);

	return 0;
}

static int open_pktios(test_global_t *global)
{
	odp_pool_capability_t pool_capa;
	odp_pktio_capability_t pktio_capa;
	odp_pool_param_t  pool_param;
	odp_pool_t pool;
	odp_pktio_param_t pktio_param;
	odp_pktio_t pktio;
	odp_pktio_config_t pktio_config;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	char *name;
	uint32_t i, seg_len;
	int j, pktio_idx;
	test_options_t *test_options = &global->test_options;
	int num_rx = test_options->num_rx;
	int num_tx = test_options->num_tx;
	uint32_t num_pktio = test_options->num_pktio;
	uint32_t num_pkt = test_options->num_pkt;
	uint32_t pkt_len = test_options->use_rand_pkt_len ?
				test_options->rand_pkt_len_max : test_options->pkt_len;
	odp_pktout_queue_t pktout[num_tx];
	odp_pktin_queue_t pktin[num_rx];

	printf("\nODP packet generator\n");
	printf("  quit test after     %" PRIu64 " rounds\n",
	       test_options->quit);
	printf("  num rx threads      %i\n", num_rx);
	printf("  num tx threads      %i\n", num_tx);
	printf("  num packets         %u\n", num_pkt);
	if (test_options->use_rand_pkt_len)
		printf("  packet length       %u-%u bytes, %u bins\n",
		       test_options->rand_pkt_len_min,
		       test_options->rand_pkt_len_max,
		       test_options->rand_pkt_len_bins);
	else
		printf("  packet length       %u bytes\n", pkt_len);
	printf("  MTU:                ");
	if (test_options->mtu)
		printf("%u bytes\n", test_options->mtu);
	else
		printf("interface default\n");
	printf("  packet input mode:  %s\n", test_options->direct_rx ? "direct" : "scheduler");
	printf("  promisc mode:       %s\n", test_options->promisc_mode ? "enabled" : "disabled");
	printf("  transmit mode:      %i\n", test_options->tx_mode);
	printf("  measure latency:    %s\n", test_options->calc_latency ? "enabled" : "disabled");
	printf("  UDP checksum:       %s\n", test_options->calc_cs ? "enabled" : "disabled");
	printf("  payload filling:    %s\n", test_options->fill_pl ? "enabled" : "disabled");
	printf("  tx burst size       %u\n", test_options->burst_size);
	printf("  tx bursts           %u\n", test_options->bursts);
	printf("  tx burst gap        %" PRIu64 " nsec\n",
	       test_options->gap_nsec);
	printf("  clock resolution    %" PRIu64 " Hz\n", odp_time_local_res());
	for (i = 0; i < test_options->num_vlan; i++) {
		printf("  VLAN[%i]             %x:%x\n", i,
		       test_options->vlan[i].tpid, test_options->vlan[i].tci);
	}
	printf("  IPv4 source         %s\n", test_options->ipv4_src_s);
	printf("  IPv4 destination    %s\n", test_options->ipv4_dst_s);
	printf("  L4 protocol:        %s\n",
	       test_options->l4_proto == L4_PROTO_UDP ? "UDP" : "TCP");
	printf("  source port         %u\n", test_options->src_port);
	printf("  destination port    %u\n", test_options->dst_port);
	printf("  src port count      %u\n", test_options->c_mode.src_port);
	printf("  dst port count      %u\n", test_options->c_mode.dst_port);
	printf("  num pktio           %u\n", num_pktio);

	printf("  interfaces names:   ");
	for (i = 0; i < num_pktio; i++) {
		if (i > 0)
			printf("                      ");
		printf("%s\n", test_options->pktio_name[i]);
	}

	printf("  destination MACs:   ");
	for (i = 0; i < num_pktio; i++) {
		uint8_t *eth_dst = global->pktio[i].eth_dst.addr;

		if (i > 0)
			printf("                      ");
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
		       eth_dst[0], eth_dst[1], eth_dst[2],
		       eth_dst[3], eth_dst[4], eth_dst[5]);
	}
	printf("\n");

	global->pool = ODP_POOL_INVALID;

	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("Error: Pool capability failed.\n");
		return -1;
	}

	if (pool_capa.pkt.max_num &&
	    num_pkt > pool_capa.pkt.max_num) {
		ODPH_ERR("Error: Too many packets. Max %u supported.\n", pool_capa.pkt.max_num);
		return -1;
	}

	if (pool_capa.pkt.max_len && pkt_len > pool_capa.pkt.max_len) {
		ODPH_ERR("Error: Too large packets. Max %u supported length.\n",
			 pool_capa.pkt.max_len);
		return -1;
	}

	seg_len = test_options->hdr_len;
	if (pool_capa.pkt.max_seg_len &&
	    seg_len > pool_capa.pkt.max_seg_len) {
		ODPH_ERR("Error: Max segment length is too small %u\n", pool_capa.pkt.max_seg_len);
		return -1;
	}

	/* Create pool */
	odp_pool_param_init(&pool_param);
	pool_param.type        = ODP_POOL_PACKET;
	pool_param.pkt.num     = num_pkt;
	pool_param.pkt.len     = pkt_len;
	pool_param.pkt.seg_len = seg_len;

	pool = odp_pool_create("packet gen pool", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: Pool create failed.\n");
		return -1;
	}

	global->pool = pool;

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode = num_rx ? (test_options->direct_rx ?
					ODP_PKTIN_MODE_DIRECT : ODP_PKTIN_MODE_SCHED) :
					ODP_PKTIN_MODE_DISABLED;

	pktio_param.out_mode = num_tx ? ODP_PKTOUT_MODE_DIRECT : ODP_PKTOUT_MODE_DISABLED;

	for (i = 0; i < num_pktio; i++)
		global->pktio[i].pktio = ODP_PKTIO_INVALID;

	/* Open and configure interfaces */
	for (i = 0; i < num_pktio; i++) {
		name  = test_options->pktio_name[i];
		pktio = odp_pktio_open(name, pool, &pktio_param);

		if (pktio == ODP_PKTIO_INVALID) {
			ODPH_ERR("Error (%s): Pktio open failed.\n", name);
			return -1;
		}

		global->pktio[i].pktio = pktio;

		odp_pktio_print(pktio);

		pktio_idx = odp_pktio_index(pktio);
		if (pktio_idx < 0) {
			ODPH_ERR("Error (%s): Reading pktio index failed: %i\n", name, pktio_idx);
			return -1;
		}
		global->if_from_pktio_idx[pktio_idx] = i;

		if (odp_pktio_capability(pktio, &pktio_capa)) {
			ODPH_ERR("Error (%s): Pktio capability failed.\n", name);
			return -1;
		}

		if (num_rx > (int)pktio_capa.max_input_queues) {
			ODPH_ERR("Error (%s): Too many RX threads. Interface supports max %u input queues.\n",
				 name, pktio_capa.max_input_queues);
			return -1;
		}

		if (num_tx > (int)pktio_capa.max_output_queues) {
			ODPH_ERR("Error (%s): Too many TX threads. Interface supports max %u output queues.\n",
				 name, pktio_capa.max_output_queues);
			return -1;
		}

		if (odp_pktio_mac_addr(pktio,
				       &global->pktio[i].eth_src.addr,
				       ODPH_ETHADDR_LEN) != ODPH_ETHADDR_LEN) {
			ODPH_ERR("Error (%s): MAC address read failed.\n", name);
			return -1;
		}

		if (test_options->mtu) {
			uint32_t maxlen_input = pktio_capa.maxlen.max_input ? test_options->mtu : 0;
			uint32_t maxlen_output = pktio_capa.maxlen.max_output ?
							test_options->mtu : 0;

			if (!pktio_capa.set_op.op.maxlen) {
				ODPH_ERR("Error (%s): modifying interface MTU not supported.\n",
					 name);
				return -1;
			}

			if (maxlen_input &&
			    (maxlen_input < pktio_capa.maxlen.min_input ||
			     maxlen_input > pktio_capa.maxlen.max_input)) {
				ODPH_ERR("Error (%s): unsupported MTU value %" PRIu32 " "
					 "(min %" PRIu32 ", max %" PRIu32 ")\n", name, maxlen_input,
					 pktio_capa.maxlen.min_input, pktio_capa.maxlen.max_input);
				return -1;
			}
			if (maxlen_output &&
			    (maxlen_output < pktio_capa.maxlen.min_output ||
			     maxlen_output > pktio_capa.maxlen.max_output)) {
				ODPH_ERR("Error (%s): unsupported MTU value %" PRIu32 " "
					 "(min %" PRIu32 ", max %" PRIu32 ")\n", name,
					 maxlen_output, pktio_capa.maxlen.min_output,
					 pktio_capa.maxlen.max_output);
				return -1;
			}

			if (odp_pktio_maxlen_set(pktio, maxlen_input, maxlen_output)) {
				ODPH_ERR("Error (%s): setting MTU failed\n", name);
				return -1;
			}
		}

		if (test_options->tx_mode == TX_MODE_DF && pktio_capa.free_ctrl.dont_free == 0) {
			ODPH_ERR("Error (%s): Don't free mode not supported\n", name);
			return -1;
		}

		odp_pktio_config_init(&pktio_config);
		pktio_config.parser.layer = ODP_PROTO_LAYER_ALL;

		odp_pktio_config(pktio, &pktio_config);

		if (test_options->promisc_mode && odp_pktio_promisc_mode(pktio) != 1) {
			if (!pktio_capa.set_op.op.promisc_mode) {
				ODPH_ERR("Error (%s): promisc mode set not supported\n", name);
				return -1;
			}

			if (odp_pktio_promisc_mode_set(pktio, true)) {
				ODPH_ERR("Error (%s): promisc mode enable failed\n", name);
				return -1;
			}
		}

		odp_pktin_queue_param_init(&pktin_param);

		if (test_options->direct_rx) {
			pktin_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
		} else {
			pktin_param.queue_param.sched.prio  = odp_schedule_default_prio();
			pktin_param.queue_param.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
			pktin_param.queue_param.sched.group = ODP_SCHED_GROUP_ALL;
		}

		pktin_param.num_queues = num_rx;

		if (num_rx > 1) {
			pktin_param.hash_enable = 1;
			pktin_param.hash_proto.proto.ipv4_udp = 1;
		}

		if (odp_pktin_queue_config(pktio, &pktin_param)) {
			ODPH_ERR("Error (%s): Pktin config failed.\n", name);
			return -1;
		}

		odp_pktout_queue_param_init(&pktout_param);
		pktout_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
		pktout_param.num_queues = num_tx;

		if (odp_pktout_queue_config(pktio, &pktout_param)) {
			ODPH_ERR("Error (%s): Pktout config failed.\n", name);
			return -1;
		}

		if (num_tx > 0) {
			if (odp_pktout_queue(pktio, pktout, num_tx) != num_tx) {
				ODPH_ERR("Error (%s): Pktout queue request failed.\n", name);
				return -1;
			}

			for (j = 0; j < num_tx; j++)
				global->pktio[i].pktout[j] = pktout[j];
		}

		if (num_rx > 0 && test_options->direct_rx) {
			if (odp_pktin_queue(pktio, pktin, num_rx) != num_rx) {
				ODPH_ERR("Error (%s): Pktin queue request failed.\n", name);
				return -1;
			}

			for (j = 0; j < num_rx; j++)
				global->pktio[i].pktin[j] = pktin[j];
		}
	}

	return 0;
}

static int print_link_info(odp_pktio_t pktio)
{
	odp_pktio_link_info_t info;

	if (odp_pktio_link_info(pktio, &info)) {
		ODPH_ERR("Error: Pktio link info failed.\n");
		return -1;
	}

	printf("  autoneg     %s\n",
	       (info.autoneg == ODP_PKTIO_LINK_AUTONEG_ON ? "on" :
	       (info.autoneg == ODP_PKTIO_LINK_AUTONEG_OFF ? "off" : "unknown")));
	printf("  duplex      %s\n",
	       (info.duplex == ODP_PKTIO_LINK_DUPLEX_HALF ? "half" :
	       (info.duplex == ODP_PKTIO_LINK_DUPLEX_FULL ? "full" : "unknown")));
	printf("  media       %s\n", info.media);
	printf("  pause_rx    %s\n",
	       (info.pause_rx == ODP_PKTIO_LINK_PAUSE_ON ? "on" :
	       (info.pause_rx == ODP_PKTIO_LINK_PAUSE_OFF ? "off" : "unknown")));
	printf("  pause_tx    %s\n",
	       (info.pause_tx == ODP_PKTIO_LINK_PAUSE_ON ? "on" :
	       (info.pause_tx == ODP_PKTIO_LINK_PAUSE_OFF ? "off" : "unknown")));
	printf("  speed(Mbit/s) %" PRIu32 "\n\n", info.speed);

	return 0;
}

static int start_pktios(test_global_t *global)
{
	uint32_t i;
	test_options_t *test_options = &global->test_options;
	uint32_t num_pktio = test_options->num_pktio;
	uint32_t link_wait = 0;

	for (i = 0; i < num_pktio; i++) {
		if (odp_pktio_start(global->pktio[i].pktio)) {
			ODPH_ERR("Error (%s): Pktio start failed.\n", test_options->pktio_name[i]);

			return -1;
		}

		global->pktio[i].started = 1;
	}

	/* Wait until all links are up */
	for (i = 0; test_options->wait_sec && i < num_pktio; i++) {
		while (1) {
			odp_pktio_t pktio = global->pktio[i].pktio;

			if (odp_pktio_link_status(pktio) == ODP_PKTIO_LINK_STATUS_UP) {
				printf("pktio:%s\n", test_options->pktio_name[i]);
				if (print_link_info(pktio)) {
					ODPH_ERR("Error (%s): Printing link info failed.\n",
						 test_options->pktio_name[i]);
					return -1;
				}
				break;
			}
			link_wait++;
			if (link_wait > test_options->wait_sec) {
				ODPH_ERR("Error (%s): Pktio link down.\n",
					 test_options->pktio_name[i]);
				return -1;
			}
			odp_time_wait_ns(ODP_TIME_SEC_IN_NS);
		}
	}

	if (test_options->wait_start_sec)
		odp_time_wait_ns(test_options->wait_start_sec * ODP_TIME_SEC_IN_NS);

	return 0;
}

static int stop_pktios(test_global_t *global)
{
	uint32_t i;
	odp_pktio_t pktio;
	int ret = 0;
	test_options_t *test_options = &global->test_options;
	uint32_t num_pktio = test_options->num_pktio;

	for (i = 0; i < num_pktio; i++) {
		pktio = global->pktio[i].pktio;

		if (pktio == ODP_PKTIO_INVALID || global->pktio[i].started == 0)
			continue;

		if (odp_pktio_stop(pktio)) {
			ODPH_ERR("Error (%s): Pktio stop failed.\n", test_options->pktio_name[i]);
			ret = -1;
		}
	}

	return ret;
}

static int close_pktios(test_global_t *global)
{
	uint32_t i;
	odp_pktio_t pktio;
	test_options_t *test_options = &global->test_options;
	uint32_t num_pktio = test_options->num_pktio;
	int ret = 0;

	for (i = 0; i < num_pktio; i++) {
		pktio = global->pktio[i].pktio;

		if (pktio == ODP_PKTIO_INVALID)
			continue;

		if (odp_pktio_close(pktio)) {
			ODPH_ERR("Error (%s): Pktio close failed.\n", test_options->pktio_name[i]);
			ret = -1;
		}
	}

	if (global->pool != ODP_POOL_INVALID &&
	    odp_pool_destroy(global->pool)) {
		ODPH_ERR("Error: Pool destroy failed.\n");
		ret = -1;
	}

	return ret;
}

static inline void get_timestamp(odp_packet_t pkt, uint32_t ts_off, rx_lat_data_t *lat_data,
				 uint64_t rx_ts)
{
	ts_data_t ts_data;
	uint64_t nsec;

	if (odp_unlikely(odp_packet_copy_to_mem(pkt, ts_off, sizeof(ts_data), &ts_data) < 0 ||
			 ts_data.magic != TS_MAGIC))
		return;

	nsec = rx_ts - ts_data.tx_ts;

	if (nsec < lat_data->min)
		lat_data->min = nsec;

	if (nsec > lat_data->max)
		lat_data->max = nsec;

	lat_data->nsec += nsec;
	lat_data->packets++;
}

static int rx_thread(void *arg)
{
	int i, thr, num;
	uint32_t exit_test;
	uint64_t bytes;
	odp_time_t t1, t2, exit_time;
	thread_arg_t *thread_arg = arg;
	test_global_t *global = thread_arg->global;
	int direct_rx = global->test_options.direct_rx;
	int periodic_stat = global->test_options.update_msec ? 1 : 0;
	uint64_t rx_timeouts = 0;
	uint64_t rx_packets = 0;
	uint64_t rx_bytes = 0;
	uint64_t nsec = 0;
	int ret = 0;
	int clock_started = 0;
	int exit_timer_started = 0;
	int paused = 0;
	const int max_num = 32;
	int pktin = 0;
	int num_pktio = global->test_options.num_pktio;
	odp_pktin_queue_t pktin_queue[num_pktio];
	odp_packet_t pkt[max_num];
	uint32_t ts_off = global->test_options.calc_latency ? global->test_options.hdr_len : 0;
	uint64_t rx_ts = 0;
	rx_lat_data_t rx_lat_data = { .nsec = 0, .min = UINT64_MAX, .max = 0, .packets = 0 };

	thr = odp_thread_id();
	global->stat[thr].thread_type = RX_THREAD;

	if (direct_rx) {
		for (i = 0; i < num_pktio; i++)
			pktin_queue[i] = thread_arg->pktin[i];
	}

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	while (1) {
		if (direct_rx) {
			num = odp_pktin_recv(pktin_queue[pktin], pkt, max_num);

			if (odp_unlikely(num < 0)) {
				ODPH_ERR("pktin (%i) recv failed: %i\n", pktin, num);
				ret = -1;
				num = 0;
				break;
			}

			pktin++;
			if (pktin >= num_pktio)
				pktin = 0;
		} else {
			odp_event_t ev[max_num];

			num = odp_schedule_multi_no_wait(NULL, ev, max_num);

			if (num)
				odp_packet_from_event_multi(pkt, ev, num);
		}

		if (ts_off && num)
			rx_ts = odp_time_global_ns();

		exit_test = odp_atomic_load_u32(&global->exit_test);
		if (exit_test) {
			/* Wait 1 second for possible in flight packets sent by the tx threads */
			if (exit_timer_started == 0) {
				exit_time = odp_time_local();
				t2 = exit_time;
				exit_timer_started = 1;
			} else if (odp_time_diff_ns(odp_time_local(), exit_time) >
				   ODP_TIME_SEC_IN_NS) {
				if (direct_rx == 0 && paused == 0) {
					odp_schedule_pause();
					paused = 1;
				} else if (num == 0) {
					/* Exit main loop after (schedule paused and) no more
					 * packets received */
					break;
				}
			}
			/* Use last received packet as stop time and don't increase rx_timeouts
			 * counter since tx threads have already been stopped */
			if (num)
				t2 = odp_time_local();
			else
				continue;
		}

		if (num == 0) {
			if (direct_rx == 0)
				rx_timeouts++;

			continue;
		}

		if (!clock_started) {
			t1 = odp_time_local();
			clock_started = 1;
		}

		bytes = 0;
		for (i = 0; i < num; i++) {
			bytes += odp_packet_len(pkt[i]);

			if (ts_off)
				get_timestamp(pkt[i], ts_off, &rx_lat_data, rx_ts);
		}

		rx_packets += num;
		rx_bytes   += bytes;

		if (odp_unlikely(periodic_stat)) {
			/* All packets from the same queue are from the same pktio interface */
			int index = odp_packet_input_index(pkt[0]);

			if (index >= 0) {
				int if_idx = global->if_from_pktio_idx[index];

				global->stat[thr].pktio[if_idx].rx_packets += num;
			}
		}

		odp_packet_free_multi(pkt, num);
	}

	if (clock_started)
		nsec = odp_time_diff_ns(t2, t1);

	/* Update stats*/
	global->stat[thr].time_nsec       = nsec;
	global->stat[thr].rx_timeouts     = rx_timeouts;
	global->stat[thr].rx_packets      = rx_packets;
	global->stat[thr].rx_bytes        = rx_bytes;
	global->stat[thr].rx_lat_nsec     = rx_lat_data.nsec;
	global->stat[thr].rx_lat_min_nsec = rx_lat_data.min;
	global->stat[thr].rx_lat_max_nsec = rx_lat_data.max;
	global->stat[thr].rx_lat_packets  = rx_lat_data.packets;

	return ret;
}

static void drain_scheduler(test_global_t *global)
{
	odp_event_t ev;
	uint64_t wait_time = odp_schedule_wait_time(100 * ODP_TIME_MSEC_IN_NS);

	while ((ev = odp_schedule(NULL, wait_time)) != ODP_EVENT_INVALID) {
		global->drained++;
		odp_event_free(ev);
	}
}

static void drain_direct_input(test_global_t *global)
{
	odp_pktin_queue_t pktin;
	odp_packet_t pkt;
	int i, j;
	int num_pktio = global->test_options.num_pktio;
	int num_rx = global->test_options.num_rx;

	for (i = 0; i < num_pktio; i++) {
		for (j = 0; j < num_rx; j++) {
			pktin = global->pktio[i].pktin[j];

			while (odp_pktin_recv(pktin, &pkt, 1) == 1) {
				global->drained++;
				odp_packet_free(pkt);
			}
		}
	}
}

static int init_packets(test_global_t *global, int pktio,
			odp_packet_t packet[], uint32_t num, uint16_t seq)
{
	odp_packet_t pkt;
	uint32_t i, j, pkt_len, seg_len, payload_len, l2_len;
	void *data;
	uint8_t *u8;
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	uint16_t tpid;
	test_options_t *test_options = &global->test_options;
	const odp_bool_t use_tcp = test_options->l4_proto == L4_PROTO_TCP;
	uint32_t num_vlan = test_options->num_vlan;
	uint32_t hdr_len = test_options->hdr_len;
	uint16_t src_port = test_options->src_port;
	uint16_t dst_port = test_options->dst_port;
	uint32_t src_cnt = 0;
	uint32_t dst_cnt = 0;
	uint32_t tcp_seqnum = 0x1234;
	odph_vlanhdr_t *vlan = NULL; /* Fixes bogus compiler warning */

	if (num_vlan > MAX_VLANS)
		num_vlan = MAX_VLANS;

	for (i = 0; i < num; i++) {
		pkt = packet[i];
		pkt_len = odp_packet_len(pkt);
		seg_len = odp_packet_seg_len(pkt);
		data = odp_packet_data(pkt);
		payload_len = pkt_len - hdr_len;

		if (seg_len < hdr_len) {
			ODPH_ERR("Error: First segment too short %u\n", seg_len);
			return -1;
		}

		/* Ethernet */
		eth = data;
		memcpy(eth->dst.addr, global->pktio[pktio].eth_dst.addr, 6);
		memcpy(eth->src.addr, global->pktio[pktio].eth_src.addr, 6);
		eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);
		l2_len = ODPH_ETHHDR_LEN;

		/* VLAN(s) */
		if (num_vlan) {
			tpid = test_options->vlan[0].tpid;
			eth->type = odp_cpu_to_be_16(tpid);
		}

		for (j = 0; j < num_vlan; j++) {
			vlan = (odph_vlanhdr_t *)((uint8_t *)data + l2_len);
			vlan->tci = odp_cpu_to_be_16(test_options->vlan[j].tci);
			if (j < num_vlan - 1) {
				tpid = test_options->vlan[j + 1].tpid;
				vlan->type = odp_cpu_to_be_16(tpid);
			}

			l2_len += ODPH_VLANHDR_LEN;
		}

		if (num_vlan)
			vlan->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);

		/* IPv4 */
		ip = (odph_ipv4hdr_t *)((uint8_t *)data + l2_len);
		memset(ip, 0, ODPH_IPV4HDR_LEN);
		ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
		ip->tot_len = odp_cpu_to_be_16(pkt_len - l2_len);
		ip->id = odp_cpu_to_be_16(seq + i);
		ip->ttl = 64;
		ip->proto = use_tcp ? ODPH_IPPROTO_TCP : ODPH_IPPROTO_UDP;
		ip->src_addr = odp_cpu_to_be_32(test_options->ipv4_src);
		ip->dst_addr = odp_cpu_to_be_32(test_options->ipv4_dst);
		ip->chksum = ~odp_chksum_ones_comp16(ip, ODPH_IPV4HDR_LEN);

		u8 = ((uint8_t *)data + l2_len + ODPH_IPV4HDR_LEN);

		if (use_tcp) {
			odph_tcphdr_t *tcp = (odph_tcphdr_t *)u8;

			memset(tcp, 0, ODPH_TCPHDR_LEN);
			tcp->src_port = odp_cpu_to_be_16(src_port);
			tcp->dst_port = odp_cpu_to_be_16(dst_port);
			tcp->seq_no   = odp_cpu_to_be_32(tcp_seqnum);
			tcp->ack_no   = odp_cpu_to_be_32(0x12345678);
			tcp->window   = odp_cpu_to_be_16(0x4000);
			tcp->hl       = 5;
			tcp->ack      = 1;
			tcp_seqnum   += payload_len;
		} else {
			odph_udphdr_t *udp = (odph_udphdr_t *)u8;

			memset(udp, 0, ODPH_UDPHDR_LEN);
			udp->src_port = odp_cpu_to_be_16(src_port);
			udp->dst_port = odp_cpu_to_be_16(dst_port);
			udp->length   = odp_cpu_to_be_16(payload_len + ODPH_UDPHDR_LEN);
			udp->chksum   = 0;
		}

		u8  = data;
		u8 += hdr_len;

		if (test_options->fill_pl) {
			/* Init payload until the end of the first segment */
			for (j = 0; j < seg_len - hdr_len; j++)
				u8[j] = j;
		}

		/* Insert checksum */
		odp_packet_l3_offset_set(pkt, l2_len);
		odp_packet_l4_offset_set(pkt, l2_len + ODPH_IPV4HDR_LEN);
		odp_packet_has_eth_set(pkt, 1);
		odp_packet_has_ipv4_set(pkt, 1);
		if (use_tcp) {
			odp_packet_has_tcp_set(pkt, 1);
			/* TCP checksum is always updated before TX */
		} else {
			odp_packet_has_udp_set(pkt, 1);
			if (!test_options->calc_latency && test_options->calc_cs)
				odph_udp_chksum_set(pkt);
		}

		/* Increment port numbers */
		if (test_options->c_mode.src_port) {
			src_cnt++;
			if (src_cnt < test_options->c_mode.src_port) {
				src_port++;
			} else {
				src_port = test_options->src_port;
				src_cnt = 0;
			}
		}
		if (test_options->c_mode.dst_port) {
			dst_cnt++;
			if (dst_cnt < test_options->c_mode.dst_port) {
				dst_port++;
			} else {
				dst_port = test_options->dst_port;
				dst_cnt = 0;
			}
		}
	}

	return 0;
}

static inline void update_tcp_hdr(odp_packet_t pkt, odp_packet_t base_pkt, uint32_t hdr_len)
{
	odph_tcphdr_t *tcp = odp_packet_l4_ptr(pkt, NULL);
	odph_tcphdr_t *tcp_base = odp_packet_l4_ptr(base_pkt, NULL);
	uint32_t prev_seqnum = odp_be_to_cpu_32(tcp_base->seq_no);

	tcp->seq_no = odp_cpu_to_be_32(prev_seqnum + (odp_packet_len(pkt) - hdr_len));

	/* Last used sequence number is stored in the base packet */
	tcp_base->seq_no = tcp->seq_no;

	odph_tcp_chksum_set(pkt);
}

static inline int update_rand_data(uint8_t *data, uint32_t data_len)
{
	uint32_t generated = 0;
	uint32_t retries = 0;

	while (generated < data_len) {
		int32_t  ret = odp_random_data(data, data_len - generated, ODP_RANDOM_BASIC);

		if (odp_unlikely(ret < 0)) {
			ODPH_ERR("Error: odp_random_data() failed: %" PRId32 "\n", ret);
			return -1;
		} else if (odp_unlikely(ret == 0)) {
			retries++;
			if (odp_unlikely(retries > MAX_RAND_RETRIES)) {
				ODPH_ERR("Error: Failed to create random data\n");
				return -1;
			}
			continue;
		}
		data += ret;
		generated += ret;
	}
	return 0;
}

static inline void set_timestamp(odp_packet_t pkt, uint32_t ts_off)
{
	const ts_data_t ts_data = { .magic = TS_MAGIC, .tx_ts = odp_time_global_ns() };

	(void)odp_packet_copy_from_mem(pkt, ts_off, sizeof(ts_data), &ts_data);
}

static int alloc_packets(odp_pool_t pool, odp_packet_t *pkt_tbl, uint32_t num,
			 test_global_t *global)
{
	uint32_t i, pkt_len;
	test_options_t *test_options = &global->test_options;
	uint32_t num_bins = global->num_bins;

	pkt_len = test_options->pkt_len;

	for (i = 0; i < num; i++) {
		if (num_bins)
			pkt_len = global->len_bin[i % num_bins];

		pkt_tbl[i] = odp_packet_alloc(pool, pkt_len);
		if (pkt_tbl[i] == ODP_PACKET_INVALID) {
			ODPH_ERR("Error: Alloc of %uB packet failed\n", pkt_len);
			break;
		}
	}

	if (i == 0)
		return -1;

	if (i != num) {
		odp_packet_free_multi(pkt_tbl, i);
		return -1;
	}

	return 0;
}

static inline uint32_t form_burst(odp_packet_t out_pkt[], uint32_t burst_size, uint32_t num_bins,
				  uint32_t burst, odp_packet_t *pkt_tbl, odp_pool_t pool,
				  int tx_mode, odp_bool_t calc_latency, uint32_t hdr_len,
				  odp_bool_t calc_udp_cs, uint64_t *total_bytes, uint8_t l4_proto)
{
	uint32_t i, idx;
	odp_packet_t pkt;
	static __thread int rand_idx = RAND_16BIT_WORDS;
	static __thread uint16_t rand_data[RAND_16BIT_WORDS];
	uint64_t bytes = 0;

	idx = burst * burst_size;
	if (num_bins)
		idx = burst * burst_size * num_bins;

	for (i = 0; i < burst_size; i++) {
		if (num_bins) {
			uint32_t bin;

			if (rand_idx >= RAND_16BIT_WORDS) {
				if (odp_unlikely(update_rand_data((uint8_t *)rand_data,
								  RAND_16BIT_WORDS * 2)))
					break;
				rand_idx = 0;
			}
			/* Select random length bin */
			bin = rand_data[rand_idx++] % num_bins;
			pkt = pkt_tbl[idx + bin];
			idx += num_bins;
		} else {
			pkt = pkt_tbl[idx];
			idx++;
		}

		if (tx_mode == TX_MODE_DF) {
			out_pkt[i] = pkt;
		} else if (tx_mode == TX_MODE_REF) {
			out_pkt[i] = odp_packet_ref_static(pkt);

			if (odp_unlikely(out_pkt[i] == ODP_PACKET_INVALID))
				break;
		} else {
			out_pkt[i] = odp_packet_copy(pkt, pool);

			if (odp_unlikely(out_pkt[i] == ODP_PACKET_INVALID))
				break;

			if (calc_latency)
				set_timestamp(out_pkt[i], hdr_len);

			if (l4_proto == L4_PROTO_TCP)
				update_tcp_hdr(out_pkt[i], pkt, hdr_len);
			else if (calc_latency && calc_udp_cs)
				odph_udp_chksum_set(out_pkt[i]);
		}

		bytes += odp_packet_len(out_pkt[i]);
	}

	*total_bytes = bytes;

	return i;
}

static inline uint32_t send_burst(odp_pktout_queue_t pktout, odp_packet_t pkt[],
				  uint32_t num, int tx_mode, uint64_t *drop_bytes)
{
	int ret;
	uint32_t sent;
	uint64_t bytes = 0;

	ret = odp_pktout_send(pktout, pkt, num);

	sent = ret;
	if (odp_unlikely(ret < 0))
		sent = 0;

	if (odp_unlikely(sent != num)) {
		uint32_t i;
		uint32_t num_drop = num - sent;

		for (i = sent; i < num; i++)
			bytes += odp_packet_len(pkt[i]);

		if (tx_mode != TX_MODE_DF)
			odp_packet_free_multi(&pkt[sent], num_drop);
	}

	*drop_bytes = bytes;

	return sent;
}

static int tx_thread(void *arg)
{
	int i, thr, tx_thr;
	uint32_t exit_test, num_alloc, j;
	odp_time_t t1, t2, next_tmo;
	uint64_t diff_ns, t1_nsec;
	odp_packet_t *pkt_tbl;
	thread_arg_t *thread_arg = arg;
	test_global_t *global = thread_arg->global;
	test_options_t *test_options = &global->test_options;
	int periodic_stat = test_options->update_msec ? 1 : 0;
	odp_pool_t pool = global->pool;
	uint64_t gap_nsec = test_options->gap_nsec;
	uint64_t quit = test_options->quit;
	uint64_t tx_timeouts = 0;
	uint64_t tx_bytes = 0;
	uint64_t tx_packets = 0;
	uint64_t tx_drops = 0;
	int ret = 0;
	const uint32_t hdr_len = test_options->hdr_len;
	const uint32_t burst_size = test_options->burst_size;
	const uint32_t bursts = test_options->bursts;
	const uint32_t num_tx = test_options->num_tx;
	const uint8_t l4_proto = test_options->l4_proto;
	const int tx_mode = test_options->tx_mode;
	const odp_bool_t calc_cs = test_options->calc_cs;
	const odp_bool_t calc_latency = test_options->calc_latency;
	int num_pktio = test_options->num_pktio;
	odp_pktout_queue_t pktout[num_pktio];
	uint32_t tot_packets = 0;
	uint32_t num_bins = global->num_bins;

	thr = odp_thread_id();
	tx_thr = thread_arg->tx_thr;
	global->stat[thr].thread_type = TX_THREAD;

	num_alloc = global->num_tx_pkt;
	if (num_bins)
		num_alloc = global->num_tx_pkt * num_bins;

	for (i = 0; i < num_pktio; i++) {
		int seq = i * num_alloc;

		pktout[i] = thread_arg->pktout[i];
		pkt_tbl = thread_arg->packet[i];

		if (alloc_packets(pool, pkt_tbl, num_alloc, global)) {
			ret = -1;
			break;
		}

		tot_packets += num_alloc;

		if (init_packets(global, i, pkt_tbl, num_alloc, seq)) {
			ret = -1;
			break;
		}

		if (tx_mode == TX_MODE_DF) {
			for (j = 0; j < num_alloc; j++)
				odp_packet_free_ctrl_set(pkt_tbl[j],
							 ODP_PACKET_FREE_CTRL_DONT_FREE);
		}
	}

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	t1 = odp_time_local();

	/* Start TX burst at different per thread offset */
	t1_nsec = odp_time_to_ns(t1) + gap_nsec + (tx_thr * gap_nsec / num_tx);

	while (ret == 0) {
		exit_test = odp_atomic_load_u32(&global->exit_test);
		if (exit_test)
			break;

		if (quit && tx_timeouts >= quit) {
			odp_atomic_inc_u32(&global->exit_test);
			break;
		}

		if (gap_nsec) {
			uint64_t nsec = t1_nsec + tx_timeouts * gap_nsec;

			next_tmo = odp_time_local_from_ns(nsec);
			odp_time_wait_until(next_tmo);
		}
		tx_timeouts++;

		/* Send bursts to each pktio */
		for (i = 0; i < num_pktio; i++) {
			uint32_t num, sent;
			uint64_t total_bytes, drop_bytes;
			odp_packet_t pkt[burst_size];

			pkt_tbl = thread_arg->packet[i];

			for (j = 0; j < bursts; j++) {
				num = form_burst(pkt, burst_size, num_bins, j, pkt_tbl, pool,
						 tx_mode, calc_latency, hdr_len, calc_cs,
						 &total_bytes, l4_proto);

				if (odp_unlikely(num == 0)) {
					ret = -1;
					tx_drops += burst_size;
					break;
				}

				sent = send_burst(pktout[i], pkt, num, tx_mode, &drop_bytes);

				if (odp_unlikely(sent == 0)) {
					ret = -1;
					tx_drops += burst_size;
					break;
				}

				tx_bytes   += total_bytes - drop_bytes;
				tx_packets += sent;
				if (odp_unlikely(sent < burst_size))
					tx_drops += burst_size - sent;

				if (odp_unlikely(periodic_stat))
					global->stat[thr].pktio[i].tx_packets += sent;
			}
		}
	}

	t2 = odp_time_local();
	diff_ns = odp_time_diff_ns(t2, t1);

	for (i = 0; i < num_pktio; i++) {
		pkt_tbl = thread_arg->packet[i];

		if (tot_packets == 0)
			break;

		odp_packet_free_multi(pkt_tbl, num_alloc);
		tot_packets -= num_alloc;
	}

	/* Update stats */
	global->stat[thr].time_nsec   = diff_ns;
	global->stat[thr].tx_timeouts = tx_timeouts;
	global->stat[thr].tx_bytes    = tx_bytes;
	global->stat[thr].tx_packets  = tx_packets;
	global->stat[thr].tx_drops    = tx_drops;

	return ret;
}

static int start_workers(test_global_t *global, odp_instance_t instance)
{
	odph_thread_common_param_t thr_common;
	int i, j, ret, tx_thr;
	test_options_t *test_options = &global->test_options;
	int num_pktio = test_options->num_pktio;
	int num_rx  = test_options->num_rx;
	int num_cpu = test_options->num_cpu;
	odph_thread_param_t thr_param[num_cpu];

	memset(global->thread_tbl, 0, sizeof(global->thread_tbl));
	odph_thread_common_param_init(&thr_common);

	thr_common.instance = instance;
	thr_common.cpumask  = &global->cpumask;

	/* Receive threads */
	for (i = 0; i < num_rx; i++) {
		/* In direct mode, dedicate a pktin queue per pktio interface (per RX thread) */
		for (j = 0; test_options->direct_rx && j < num_pktio; j++)
			global->thread_arg[i].pktin[j] = global->pktio[j].pktin[i];

		odph_thread_param_init(&thr_param[i]);
		thr_param[i].start    = rx_thread;
		thr_param[i].arg      = &global->thread_arg[i];
		thr_param[i].thr_type = ODP_THREAD_WORKER;
	}

	/* Transmit threads */
	tx_thr = 0;
	for (i = num_rx; i < num_cpu; i++) {
		for (j = 0; j < num_pktio; j++) {
			odp_pktout_queue_t pktout;

			global->thread_arg[i].tx_thr = tx_thr;

			/* Dedicate a pktout queue per pktio interface
			 * (per TX thread) */
			pktout = global->pktio[j].pktout[tx_thr];
			global->thread_arg[i].pktout[j] = pktout;
		}

		odph_thread_param_init(&thr_param[i]);
		thr_param[i].start    = tx_thread;
		thr_param[i].arg      = &global->thread_arg[i];
		thr_param[i].thr_type = ODP_THREAD_WORKER;
		tx_thr++;
	}

	ret = odph_thread_create(global->thread_tbl, &thr_common, thr_param,
				 num_cpu);

	if (ret != num_cpu) {
		ODPH_ERR("Error: thread create failed %i\n", ret);
		return -1;
	}

	return 0;
}

static void print_periodic_stat(test_global_t *global, uint64_t nsec)
{
	int i, j;
	int num_pktio = global->test_options.num_pktio;
	double sec  = nsec / 1000000000.0;
	uint64_t num_tx[num_pktio];
	uint64_t num_rx[num_pktio];

	for (i = 0; i < num_pktio; i++) {
		num_tx[i] = 0;
		num_rx[i] = 0;

		for (j = 0; j < MAX_THREADS; j++) {
			if (global->stat[j].thread_type == RX_THREAD)
				num_rx[i] += global->stat[j].pktio[i].rx_packets;
			else if (global->stat[j].thread_type == TX_THREAD)
				num_tx[i] += global->stat[j].pktio[i].tx_packets;
		}
	}
	if (global->test_options.num_tx) {
		printf("  TX: %12.6fs", sec);
		for (i = 0; i < num_pktio; i++)
			printf(" %10" PRIu64 "", num_tx[i]);
		printf("\n");
	}

	if (global->test_options.num_rx) {
		printf("  RX: %12.6fs", sec);
		for (i = 0; i < num_pktio; i++)
			printf(" %10" PRIu64 "", num_rx[i]);
		printf("\n");
	}
}

static void periodic_print_loop(test_global_t *global)
{
	odp_time_t t1, t2;
	uint64_t nsec;
	int i;
	int num_pktio = global->test_options.num_pktio;

	printf("\n\nPackets per interface\n");
	printf("  Dir          Time");
	for (i = 0; i < num_pktio; i++)
		printf(" %10i", i);

	printf("\n  -----------------");
	for (i = 0; i < num_pktio; i++)
		printf("-----------");

	printf("\n");

	t1 = odp_time_local();
	while (odp_atomic_load_u32(&global->exit_test) == 0) {
		usleep(1000 * global->test_options.update_msec);
		t2 = odp_time_local();
		nsec = odp_time_diff_ns(t2, t1);
		print_periodic_stat(global, nsec);
	}
}

static void print_humanised_time(double time_nsec)
{
	if (time_nsec > ODP_TIME_SEC_IN_NS)
		printf("%.2f s\n", time_nsec / ODP_TIME_SEC_IN_NS);
	else if (time_nsec > ODP_TIME_MSEC_IN_NS)
		printf("%.2f ms\n", time_nsec / ODP_TIME_MSEC_IN_NS);
	else if (time_nsec > ODP_TIME_USEC_IN_NS)
		printf("%.2f us\n", time_nsec / ODP_TIME_USEC_IN_NS);
	else
		printf("%.0f ns\n", time_nsec);
}

static void print_humanised_latency(double lat_nsec, double lat_min_nsec, double lat_max_nsec)
{
	printf("  rx ave packet latency:      ");
	print_humanised_time(lat_nsec);
	printf("  rx min packet latency:      ");
	print_humanised_time(lat_min_nsec);
	printf("  rx max packet latency:      ");
	print_humanised_time(lat_max_nsec);
}

static int print_final_stat(test_global_t *global)
{
	int i, num_thr;
	double rx_mbit_per_sec, tx_mbit_per_sec;
	test_options_t *test_options = &global->test_options;
	int num_rx = test_options->num_rx;
	int num_tx = test_options->num_tx;
	uint64_t rx_nsec_sum = 0;
	uint64_t rx_pkt_sum = 0;
	uint64_t rx_byte_sum = 0;
	uint64_t rx_tmo_sum = 0;
	uint64_t rx_lat_nsec_sum = 0;
	uint64_t rx_lat_min_nsec = UINT64_MAX;
	uint64_t rx_lat_max_nsec = 0;
	uint64_t rx_lat_pkt_sum = 0;
	uint64_t tx_nsec_sum = 0;
	uint64_t tx_pkt_sum = 0;
	uint64_t tx_byte_sum = 0;
	uint64_t tx_drop_sum = 0;
	uint64_t tx_tmo_sum = 0;
	double rx_pkt_ave = 0.0;
	double rx_pkt_per_sec = 0.0;
	double rx_byte_per_sec = 0.0;
	double rx_pkt_len = 0.0;
	double rx_sec = 0.0;
	double rx_ave_lat_nsec = 0.0;
	double tx_pkt_per_sec = 0.0;
	double tx_byte_per_sec = 0.0;
	double tx_sec = 0.0;

	printf("\nRESULTS PER THREAD\n");
	printf("  rx thread:\n");
	printf("           1          2          3          4          5          6          7          8\n");
	printf("  ---------------------------------------------------------------------------------------\n");
	printf("  ");

	num_thr = 0;
	for (i = 0; i < MAX_THREADS; i++) {
		if (global->stat[i].thread_type != RX_THREAD)
			continue;

		if (num_thr && (num_thr % 8) == 0)
			printf("\n  ");

		printf("%10" PRIu64 " ", global->stat[i].rx_packets);
		num_thr++;
	}

	printf("\n\n");

	printf("  tx thread:\n");
	printf("           1          2          3          4          5          6          7          8\n");
	printf("  ---------------------------------------------------------------------------------------\n");
	printf("  ");

	num_thr = 0;
	for (i = 0; i < MAX_THREADS; i++) {
		if (global->stat[i].thread_type != TX_THREAD)
			continue;

		if (num_thr && (num_thr % 8) == 0)
			printf("\n  ");

		printf("%10" PRIu64 " ", global->stat[i].tx_packets);
		num_thr++;
	}

	printf("\n\n");

	for (i = 0; i < MAX_THREADS; i++) {
		if (global->stat[i].thread_type == RX_THREAD) {
			rx_tmo_sum      += global->stat[i].rx_timeouts;
			rx_pkt_sum      += global->stat[i].rx_packets;
			rx_byte_sum     += global->stat[i].rx_bytes;
			rx_nsec_sum     += global->stat[i].time_nsec;
			rx_lat_nsec_sum += global->stat[i].rx_lat_nsec;
			rx_lat_pkt_sum  += global->stat[i].rx_lat_packets;

			if (global->stat[i].rx_lat_min_nsec < rx_lat_min_nsec)
				rx_lat_min_nsec = global->stat[i].rx_lat_min_nsec;

			if (global->stat[i].rx_lat_max_nsec > rx_lat_max_nsec)
				rx_lat_max_nsec = global->stat[i].rx_lat_max_nsec;
		} else if (global->stat[i].thread_type == TX_THREAD) {
			tx_tmo_sum  += global->stat[i].tx_timeouts;
			tx_pkt_sum  += global->stat[i].tx_packets;
			tx_byte_sum += global->stat[i].tx_bytes;
			tx_drop_sum += global->stat[i].tx_drops;
			tx_nsec_sum += global->stat[i].time_nsec;
		}
	}

	if (num_rx)
		rx_pkt_ave = (double)rx_pkt_sum / num_rx;
	rx_sec = rx_nsec_sum / 1000000000.0;
	tx_sec = tx_nsec_sum / 1000000000.0;

	/* Packets and bytes per thread per sec */
	if (rx_nsec_sum) {
		rx_pkt_per_sec = (1000000000.0 * (double)rx_pkt_sum) /
				 (double)rx_nsec_sum;

		rx_byte_per_sec  = 1000000000.0;
		rx_byte_per_sec *= (rx_byte_sum + 24 * rx_pkt_sum);
		rx_byte_per_sec /= (double)rx_nsec_sum;
	}

	if (tx_nsec_sum) {
		tx_pkt_per_sec = (1000000000.0 * (double)tx_pkt_sum) /
				 (double)tx_nsec_sum;

		tx_byte_per_sec  = 1000000000.0;
		tx_byte_per_sec *= (tx_byte_sum + 24 * tx_pkt_sum);
		tx_byte_per_sec /= (double)tx_nsec_sum;
	}

	/* Total Mbit/s */
	rx_mbit_per_sec = (num_rx * 8 * rx_byte_per_sec) / 1000000.0;
	tx_mbit_per_sec = (num_tx * 8 * tx_byte_per_sec) / 1000000.0;

	if (rx_pkt_sum)
		rx_pkt_len = (double)rx_byte_sum / rx_pkt_sum;

	if (rx_lat_pkt_sum)
		rx_ave_lat_nsec = (double)rx_lat_nsec_sum / rx_lat_pkt_sum;

	printf("TOTAL (%i rx and %i tx threads)\n", num_rx, num_tx);
	printf("  rx timeouts:                %" PRIu64 "\n", rx_tmo_sum);
	printf("  rx time spent (sec):        %.3f\n", rx_sec);
	printf("  rx packets:                 %" PRIu64 "\n", rx_pkt_sum);
	printf("  rx packets drained:         %" PRIu64 "\n", global->drained);
	printf("  rx packets per thr:         %.1f\n", rx_pkt_ave);
	printf("  rx packets per thr per sec: %.1f\n", rx_pkt_per_sec);
	printf("  rx packets per sec:         %.1f\n", num_rx * rx_pkt_per_sec);
	printf("  rx ave packet len:          %.1f\n", rx_pkt_len);

	if (rx_lat_pkt_sum)
		print_humanised_latency(rx_ave_lat_nsec, rx_lat_min_nsec, rx_lat_max_nsec);

	printf("  rx Mbit/s:                  %.1f\n", rx_mbit_per_sec);
	printf("\n");
	printf("  tx timeouts:                %" PRIu64 "\n", tx_tmo_sum);
	printf("  tx time spent (sec):        %.3f\n", tx_sec);
	printf("  tx packets:                 %" PRIu64 "\n", tx_pkt_sum);
	printf("  tx dropped packets:         %" PRIu64 "\n", tx_drop_sum);
	printf("  tx packets per thr per sec: %.1f\n", tx_pkt_per_sec);
	printf("  tx packets per sec:         %.1f\n", num_tx * tx_pkt_per_sec);
	printf("  tx Mbit/s:                  %.1f\n", tx_mbit_per_sec);
	printf("\n");

	if (rx_pkt_sum < MIN_RX_PACKETS_CI)
		return -1;

	return 0;
}

static void sig_handler(int signo)
{
	(void)signo;

	if (test_global == NULL)
		return;

	odp_atomic_add_u32(&test_global->exit_test, 1);
}

int main(int argc, char **argv)
{
	odph_helper_options_t helper_options;
	odp_instance_t instance;
	odp_init_t init;
	test_global_t *global;
	odp_shm_t shm;
	int i;
	int ret = 0;

	signal(SIGINT, sig_handler);

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls      = 1;
	init.not_used.feat.compress = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.timer    = 1;
	init.not_used.feat.tm       = 1;

	init.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("Error: Global init failed.\n");
		return 1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Error: Local init failed.\n");
		return 1;
	}

	shm = odp_shm_reserve("packet_gen_global", sizeof(test_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: SHM reserve failed.\n");
		return 1;
	}

	global = odp_shm_addr(shm);
	test_global = global;

	memset(global, 0, sizeof(test_global_t));
	odp_atomic_init_u32(&global->exit_test, 0);

	for (i = 0; i < MAX_THREADS; i++)
		global->thread_arg[i].global = global;

	if (parse_options(argc, argv, global)) {
		ret = 1;
		goto term;
	}

	odp_sys_info_print();

	/* Avoid all scheduler API calls in direct input mode */
	if (global->test_options.direct_rx == 0)
		odp_schedule_config(NULL);

	if (set_num_cpu(global)) {
		ret = 1;
		goto term;
	}

	if (open_pktios(global)) {
		ret = 1;
		goto term;
	}

	if (start_pktios(global)) {
		ret = 1;
		goto term;
	}

	/* Start worker threads */
	start_workers(global, instance);

	/* Wait until workers have started. */
	odp_barrier_wait(&global->barrier);

	/* Periodic statistics printing */
	if (global->test_options.update_msec)
		periodic_print_loop(global);

	/* Wait workers to exit */
	odph_thread_join(global->thread_tbl,
			 global->test_options.num_cpu);

	if (stop_pktios(global))
		ret = 1;

	if (global->test_options.direct_rx)
		drain_direct_input(global);
	else
		drain_scheduler(global);

	if (close_pktios(global))
		ret = 1;

	if (print_final_stat(global))
		ret = 2;

term:
	if (odp_shm_free(shm)) {
		ODPH_ERR("Error: SHM free failed.\n");
		return 1;
	}

	if (odp_term_local()) {
		ODPH_ERR("Error: term local failed.\n");
		return 1;
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Error: term global failed.\n");
		return 1;
	}

	return ret;
}
