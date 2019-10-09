/* Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define MAX_PKTIOS        32
#define MAX_PKTIO_NAME    255
#define MAX_PKT_NUM       1024

typedef struct test_options_t {
	uint64_t num_packet;
	int verbose;
	int num_pktio;
	char pktio_name[MAX_PKTIOS][MAX_PKTIO_NAME + 1];

} test_options_t;

typedef struct test_global_t {
	test_options_t opt;
	uint64_t rx_packets;
	uint64_t tx_replies;
	odp_pool_t pool;
	int stop;

	struct {
		odph_ethaddr_t eth_addr;
		odp_pktio_t pktio;
		odp_pktout_queue_t pktout;
		int started;

	} pktio[MAX_PKTIOS];

} test_global_t;

static test_global_t test_global;

static void sig_handler(int signo)
{
	(void)signo;

	test_global.stop = 1;
	odp_mb_full();
}

static void print_usage(void)
{
	printf("\n"
	       "ODP ping example. Replies to ICMPv4 ping requests.\n"
	       "\n"
	       "OPTIONS:\n"
	       "  -i, --interface <name>      Packet IO interfaces (comma-separated, no spaces)\n"
	       "  -n, --num_packet <number>   Exit after this many packets. Use 0 to run infinitely. Default 0.\n"
	       "  -v, --verbose               Print extra packet information.\n"
	       "  -h, --help                  Display help and exit.\n\n");
}

static int parse_options(int argc, char *argv[], test_global_t *global)
{
	int i, opt, long_index;
	char *name, *str;
	int len, str_len;

	const struct option longopts[] = {
		{"interface",   required_argument, NULL, 'i'},
		{"num_packet",  required_argument, NULL, 'n'},
		{"verbose",     no_argument,       NULL, 'v'},
		{"help",        no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	const char *shortopts =  "+i:n:vh";
	int ret = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'i':
			i = 0;
			str = optarg;
			str_len = strlen(str);

			while (str_len > 0) {
				len = strcspn(str, ",");
				str_len -= len + 1;

				if (i == MAX_PKTIOS) {
					printf("Error: Too many interfaces\n");
					ret = -1;
					break;
				}

				if (len > MAX_PKTIO_NAME) {
					printf("Error: Too long interface name %s\n",
					       str);
					ret = -1;
					break;
				}

				name = global->opt.pktio_name[i];
				memcpy(name, str, len);
				str += len + 1;
				i++;
			}

			global->opt.num_pktio = i;

			break;
		case 'n':
			global->opt.num_packet = atoll(optarg);
			break;
		case 'v':
			global->opt.verbose = 1;
			break;
		case 'h':
		default:
			print_usage();
			return -1;
		}
	}

	if (global->opt.num_pktio == 0) {
		printf("Error: At least one pktio interface needed.\n");
		ret = -1;
	}

	return ret;
}

static int open_pktios(test_global_t *global)
{
	odp_pool_param_t  pool_param;
	odp_pktio_param_t pktio_param;
	odp_pool_t pool;
	odp_pool_capability_t pool_capa;
	odp_pktio_t pktio;
	odp_pktio_config_t pktio_config;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	odp_pktout_queue_t pktout;
	char *name;
	int i, num_pktio;
	uint32_t num_pkt = MAX_PKT_NUM;

	num_pktio = global->opt.num_pktio;

	if (odp_pool_capability(&pool_capa)) {
		printf("Error: Pool capability failed.\n");
		return -1;
	}

	if (pool_capa.pkt.max_num < MAX_PKT_NUM)
		num_pkt = pool_capa.pkt.max_num;

	odp_pool_param_init(&pool_param);
	pool_param.pkt.num     = num_pkt;
	pool_param.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet pool", &pool_param);

	global->pool = pool;

	if (pool == ODP_POOL_INVALID) {
		printf("Error: Pool create.\n");
		return -1;
	}

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode  = ODP_PKTIN_MODE_SCHED;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	for (i = 0; i < num_pktio; i++)
		global->pktio[i].pktio = ODP_PKTIO_INVALID;

	/* Open and configure interfaces */
	for (i = 0; i < num_pktio; i++) {
		name  = global->opt.pktio_name[i];
		pktio = odp_pktio_open(name, pool, &pktio_param);

		if (pktio == ODP_PKTIO_INVALID) {
			printf("Error (%s): Pktio open failed.\n", name);
			return -1;
		}

		global->pktio[i].pktio = pktio;

		odp_pktio_print(pktio);

		if (odp_pktio_mac_addr(pktio,
				       &global->pktio[i].eth_addr.addr,
				       ODPH_ETHADDR_LEN) != ODPH_ETHADDR_LEN) {
			printf("Error (%s): MAC address read failed.\n", name);
			return -1;
		}

		odp_pktio_config_init(&pktio_config);
		pktio_config.pktin.bit.ts_all = 1;
		pktio_config.parser.layer = ODP_PROTO_LAYER_ALL;

		odp_pktio_config(pktio, &pktio_config);

		odp_pktin_queue_param_init(&pktin_param);

		pktin_param.queue_param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		pktin_param.queue_param.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
		pktin_param.queue_param.sched.group = ODP_SCHED_GROUP_ALL;
		pktin_param.num_queues = 1;

		if (odp_pktin_queue_config(pktio, &pktin_param)) {
			printf("Error (%s): Pktin config failed.\n", name);
			return -1;
		}

		odp_pktout_queue_param_init(&pktout_param);
		pktout_param.num_queues = 1;

		if (odp_pktout_queue_config(pktio, &pktout_param)) {
			printf("Error (%s): Pktout config failed.\n", name);
			return -1;
		}

		if (odp_pktout_queue(pktio, &pktout, 1) != 1) {
			printf("Error (%s): Pktout queue request failed.\n",
			       name);
			return -1;
		}

		global->pktio[i].pktout = pktout;
	}

	return 0;
}

static int start_pktios(test_global_t *global)
{
	int i;

	for (i = 0; i < global->opt.num_pktio; i++) {
		if (odp_pktio_start(global->pktio[i].pktio)) {
			printf("Error (%s): Pktio start failed.\n",
			       global->opt.pktio_name[i]);

			return -1;
		}

		global->pktio[i].started = 1;
	}

	return 0;
}

static int stop_pktios(test_global_t *global)
{
	odp_pktio_t pktio;
	int i, ret = 0;

	for (i = 0; i < global->opt.num_pktio; i++) {
		pktio = global->pktio[i].pktio;

		if (pktio == ODP_PKTIO_INVALID || global->pktio[i].started == 0)
			continue;

		if (odp_pktio_stop(pktio)) {
			printf("Error (%s): Pktio stop failed.\n",
			       global->opt.pktio_name[i]);
			ret = -1;
		}
	}

	return ret;
}

static void empty_queues(void)
{
	odp_event_t ev;
	uint64_t wait_time = odp_schedule_wait_time(ODP_TIME_SEC_IN_NS / 2);

	/* Drop all events from all queues */
	while (1) {
		ev = odp_schedule(NULL, wait_time);

		if (ev == ODP_EVENT_INVALID)
			break;

		odp_event_free(ev);
	}
}

static int close_pktios(test_global_t *global)
{
	odp_pktio_t pktio;
	odp_pool_t pool;
	int i, ret = 0;

	for (i = 0; i < global->opt.num_pktio; i++) {
		pktio = global->pktio[i].pktio;

		if (pktio == ODP_PKTIO_INVALID)
			continue;

		if (odp_pktio_close(pktio)) {
			printf("Error (%s): Pktio close failed.\n",
			       global->opt.pktio_name[i]);
			ret = -1;
		}
	}

	pool = global->pool;

	if (pool == ODP_POOL_INVALID)
		return ret;

	if (odp_pool_destroy(pool)) {
		printf("Error: Pool destroy failed.\n");
		ret = -1;
	}

	return ret;
}

static void print_mac_addr(uint8_t *addr)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
	       addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static void print_ipv4_addr(uint8_t *addr)
{
	printf("%u.%u.%u.%u\n",
	       addr[0], addr[1], addr[2], addr[3]);
}

static void print_data(odp_packet_t pkt, uint32_t offset, uint32_t len)
{
	const uint32_t bytes_per_row = 16;
	const uint32_t num_char = 1 + (bytes_per_row * 3) + 1;
	uint8_t data[bytes_per_row];
	char row[num_char];
	uint32_t copy_len, i, j;
	uint32_t data_len = odp_packet_len(pkt);

	if (offset > data_len)
		return;

	if (offset + len > data_len)
		len = data_len - offset;

	while (len) {
		i = 0;

		if (len > bytes_per_row)
			copy_len = bytes_per_row;
		else
			copy_len = len;

		odp_packet_copy_to_mem(pkt, offset, copy_len, data);

		i += snprintf(&row[i], num_char - i, " ");

		for (j = 0; j < copy_len; j++)
			i += snprintf(&row[i], num_char - i, " %02x", data[j]);

		row[i] = 0;
		printf("%s\n", row);

		len    -= copy_len;
		offset += copy_len;
	}
}

static void print_packet(odp_packet_t pkt, uint64_t num_packet)
{
	odp_pktio_t pktio;
	odp_pktio_info_t pktio_info;
	odp_time_t time;
	uint64_t sec, nsec;
	uint32_t offset;
	uint8_t *data = odp_packet_data(pkt);
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint32_t l2_offset = odp_packet_l2_offset(pkt);
	uint32_t l3_offset = odp_packet_l3_offset(pkt);
	uint32_t l4_offset = odp_packet_l4_offset(pkt);
	uint32_t data_len = odp_packet_len(pkt);
	int icmp = odp_packet_has_icmp(pkt);
	int ipv4 = odp_packet_has_ipv4(pkt);

	if (odp_packet_has_ts(pkt))
		time = odp_packet_ts(pkt);
	else
		time = odp_time_local();

	nsec  = odp_time_to_ns(time);
	sec   = nsec / ODP_TIME_SEC_IN_NS;
	nsec  = nsec - (sec * ODP_TIME_SEC_IN_NS);
	pktio = odp_packet_input(pkt);

	odp_pktio_info(pktio, &pktio_info);

	printf("PACKET [%" PRIu64 "]\n", num_packet);
	printf("  time:            %" PRIu64 ".%09" PRIu64 " sec\n", sec, nsec);
	printf("  interface name:  %s\n", pktio_info.name);
	printf("  packet length:   %u bytes\n", odp_packet_len(pkt));

	/* L2 */
	if (odp_packet_has_eth(pkt)) {
		printf("  Ethernet offset: %u bytes\n", l2_offset);
		offset = l2_offset;
		if (offset + 6 <= seg_len) {
			printf("    dst address:   ");
			print_mac_addr(data + offset);
		}

		offset = l2_offset + 6;
		if (offset + 6 <= seg_len) {
			printf("    src address:   ");
			print_mac_addr(data + offset);
		}
	} else if (odp_packet_has_l2(pkt)) {
		printf("  L2 (%i) offset:   %u bytes\n",
		       odp_packet_l2_type(pkt), l2_offset);
	}

	/* L3 */
	if (ipv4) {
		printf("  IPv4 offset:     %u bytes\n", l3_offset);
		offset = l3_offset + 12;
		if (offset + 4 <= seg_len) {
			printf("    src address:   ");
			print_ipv4_addr(data + offset);
		}

		offset = l3_offset + 16;
		if (offset + 4 <= seg_len) {
			printf("    dst address:   ");
			print_ipv4_addr(data + offset);
		}
	} else if (odp_packet_has_ipv6(pkt)) {
		printf("  IPv6 offset:     %u bytes\n", l3_offset);
	} else if (odp_packet_has_l3(pkt)) {
		printf("  L3 (%i) offset:   %u bytes\n",
		       odp_packet_l3_type(pkt), l3_offset);
	}

	/* L4 */
	if (icmp) {
		printf("  ICMP offset:     %u bytes\n", l4_offset);
		if (ipv4) {
			uint32_t len;
			uint8_t *u8 = odp_packet_l4_ptr(pkt, &len);

			if (u8 && len >= 2) {
				printf("    type:          %u\n", u8[0]);
				printf("    code:          %u\n", u8[1]);
			}
		}
	} else if (odp_packet_has_l4(pkt)) {
		printf("  L4 (%i) offset:   %u bytes\n",
		       odp_packet_l4_type(pkt), l4_offset);
	}

	print_data(pkt, 0, data_len);

	printf("\n");
}

/* Updated checksum when a 16 bit word has been changed from old to new */
static uint16_t update_chksum(uint16_t chksum, uint16_t old, uint16_t new)
{
	uint16_t chksum_comp = ~chksum;
	uint16_t old_comp = ~old;
	uint32_t sum = chksum_comp + old_comp + new;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static void icmp_reply(test_global_t *global, odp_packet_t pkt)
{
	uint32_t dst_ip;
	odph_ipv4hdr_t *ip_hdr;
	odph_ethhdr_t *eth_hdr;
	uint16_t old, new;
	uint32_t len = 0;
	int index = odp_packet_input_index(pkt);
	odp_pktout_queue_t pktout = global->pktio[index].pktout;
	odph_ethaddr_t *eth_addr = &global->pktio[index].eth_addr;
	int icmp = odp_packet_has_icmp(pkt);
	int ipv4 = odp_packet_has_ipv4(pkt);
	int eth  = odp_packet_has_eth(pkt);
	odph_icmphdr_t *icmp_hdr = odp_packet_l4_ptr(pkt, &len);

	if (odp_packet_has_error(pkt))
		goto error;

	if (eth == 0 || ipv4 == 0 || icmp == 0)
		goto error;

	/* ICMP type, code and chksum fields are located in the first 4 bytes */
	if (icmp_hdr == NULL || len < 4)
		goto error;

	if (icmp_hdr->type != 8 || icmp_hdr->code != 0)
		goto error;

	/* Echo reply */
	old = *(uint16_t *)(uintptr_t)icmp_hdr;
	icmp_hdr->type = 0;
	new = *(uint16_t *)(uintptr_t)icmp_hdr;
	icmp_hdr->chksum = update_chksum(icmp_hdr->chksum, old, new);

	/* Swap IP addresses */
	ip_hdr = odp_packet_l3_ptr(pkt, &len);
	if (ip_hdr == NULL || len < 20)
		goto error;

	dst_ip = ip_hdr->dst_addr;
	ip_hdr->dst_addr = ip_hdr->src_addr;
	ip_hdr->src_addr = dst_ip;

	/* Swap Ethernet addresses */
	eth_hdr = odp_packet_l2_ptr(pkt, &len);
	if (eth_hdr == NULL || len < 14)
		goto error;

	eth_hdr->dst = eth_hdr->src;
	eth_hdr->src = *eth_addr;

	if (odp_pktout_send(pktout, &pkt, 1) != 1)
		goto error;

	global->tx_replies++;
	return;

error:
	odp_packet_free(pkt);
}

static void print_stat(test_global_t *global, uint64_t rx_packets,
		       uint64_t diff_ns)
{
	uint64_t prev = global->rx_packets;
	double per_sec = 1000000000.0 * (rx_packets - prev) / diff_ns;

	printf("Received %" PRIu64 " packets (%.1f / sec). "
	       "Sent %" PRIu64 " replies.\n",
	       rx_packets, per_sec, global->tx_replies);

	global->rx_packets = rx_packets;
}

static int receive_packets(test_global_t *global)
{
	odp_event_t ev;
	odp_packet_t pkt;
	uint64_t diff_ns;
	int print = 0;
	uint64_t num_packet = 0;
	uint64_t wait = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS);
	odp_time_t cur = odp_time_local();
	odp_time_t prev = cur;

	while (!global->stop) {
		ev = odp_schedule(NULL, wait);

		cur = odp_time_local();
		diff_ns = odp_time_diff_ns(cur, prev);
		if (diff_ns >= ODP_TIME_SEC_IN_NS) {
			prev = cur;
			print = 1;
		}

		if (ev == ODP_EVENT_INVALID) {
			if (print) {
				print_stat(global, num_packet, diff_ns);
				print = 0;
			}
			continue;
		}

		if (odp_event_type(ev) != ODP_EVENT_PACKET) {
			printf("Bad event type: %i\n", odp_event_type(ev));
			odp_event_free(ev);
			continue;
		}

		pkt = odp_packet_from_event(ev);

		if (global->opt.verbose)
			print_packet(pkt, num_packet);

		/* Reply or drop packet */
		icmp_reply(global, pkt);

		num_packet++;
		if (print) {
			print_stat(global, num_packet, diff_ns);
			print = 0;
		}

		if (global->opt.num_packet &&
		    num_packet >= global->opt.num_packet)
			break;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	odp_instance_t instance;
	test_global_t *global;
	int ret = 0;

	global = &test_global;
	memset(global, 0, sizeof(test_global_t));

	signal(SIGINT, sig_handler);

	if (parse_options(argc, argv, global))
		return -1;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		printf("Error: Global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		printf("Error: Local init failed.\n");
		return -1;
	}

	global->pool = ODP_POOL_INVALID;

	odp_schedule_config(NULL);

	odp_sys_info_print();

	if (open_pktios(global)) {
		printf("Error: pktio open failed\n");
		return -1;
	}

	if (start_pktios(global)) {
		printf("Error: pktio start failed\n");
		return -1;
	}

	if (receive_packets(global)) {
		printf("Error: packet receive failed\n");
		return -1;
	}

	if (stop_pktios(global)) {
		printf("Error: pktio stop failed\n");
		return -1;
	}

	empty_queues();

	if (close_pktios(global)) {
		printf("Error: pktio close failed\n");
		return -1;
	}

	if (odp_term_local()) {
		printf("Error: term local failed.\n");
		return -1;
	}

	if (odp_term_global(instance)) {
		printf("Error: term global failed.\n");
		return -1;
	}

	return ret;
}
