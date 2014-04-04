/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP timer ping example application.
 * application open PF_INET socket, every ping send request
 * will arm timer for some duration, if ping_ack rxvd with
 * time band.. listen thread will cancel timer and free the
 * tmo_buffer.. otherwise timer expiration event will exit
 * application lead to test failure..
 *  - two thread used, one listener other one sender.
 *  - run ./odp_timer <ipadder>
 *   In ubuntu, you need run using sudo ./odp_timer <ipaddr>
 *  - so to tigger timeout explicitly.. ping with badipaddr
 *    Otherwise timeout may happen bcz of slow nw speed
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <string.h>
#include <odp.h>
#include <odp_common.h>
#include <odp_timer.h>
#include <helper/odp_chksum.h>

#define MSG_POOL_SIZE         (4*1024*1024)
#define BUF_SIZE		8
#define PING_CNT	10

static odp_timer_t test_timer_ping;
static odp_timer_tmo_t test_ping_tmo;

#define PKTSIZE      64
struct packet {
	struct icmphdr hdr;
	char msg[PKTSIZE-sizeof(struct icmphdr)];
};

int pid = -1;
struct protoent *proto;

struct sockaddr_in dst_addr;

/* local struct for ping_timer_thread argument */
typedef struct {
	pthrd_arg thrdarg;
	int result;
} ping_arg_t;

static int ping_sync_flag;

static void dump_icmp_pkt(void *buf, int bytes, int pkt_cnt)
{
	int i;
	struct iphdr *ip = buf;

	ODP_DBG("---dump icmp pkt_cnt %d------\n", pkt_cnt);
	for (i = 0; i < bytes; i++) {
		if (!(i & 15))
			ODP_DBG("\n %x:  ", i);
		ODP_DBG("%d ", ((unsigned char *)buf)[i]);
	}
	ODP_DBG("\n");
	char addrstr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET, &ip->daddr, addrstr, sizeof(addrstr));
	ODP_DBG("byte %d, Ack rxvd for msg_cnt [%d] from %s\n", bytes, pkt_cnt, addrstr);
}

static int listen_to_pingack(void)
{
	int sd, i;
	struct sockaddr_in addr;
	unsigned char buf[1024];
	int bytes, len;

	sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
	if (sd < 0) {
		ODP_ERR("Listener socket open failed\n");
		return -1;
	}

	for (i = 0; i < PING_CNT; i++) {
		len = sizeof(addr);

		bzero(buf, sizeof(buf));
		bytes = recvfrom(sd, buf, sizeof(buf), 0,
				 (struct sockaddr *)&addr,
				 (socklen_t *)&len);
		if (bytes > 0) {
			/* pkt rxvd therefore cancel the timeout */
			if (odp_timer_cancel_tmo(test_timer_ping,
						 test_ping_tmo) != 0) {
				ODP_ERR("cancel_tmo failed ..exiting listner thread\n");
				return -1;
			}

			/* cruel bad hack used for sender, listner ipc..
			 * euwww.. FIXME ..
			 */
			ping_sync_flag = true;

			odp_buffer_free(test_ping_tmo);

			dump_icmp_pkt(buf, bytes, i);
		} else {
			ODP_ERR("recvfrom operation failed for msg_cnt [%d]\n", i);
			return -1;
		}
	}

	return 0;
}

static int send_ping_request(struct sockaddr_in *addr)
{
	const int val = 255;
	uint32_t i, j;
	int sd, cnt = 1;
	struct packet pckt;

	uint64_t tick;
	odp_queue_t queue;
	odp_buffer_t buf;

	int thr;
	thr = odp_thread_id();

	sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
	if (sd < 0) {
		ODP_ERR("Sender socket open failed\n");
		return -1;
	}

	if (setsockopt(sd, SOL_IP, IP_TTL, &val, sizeof(val)) != 0) {
		ODP_ERR("Error setting TTL option\n");
		return -1;
	}
	if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0) {
		ODP_ERR("Request for nonblocking I/O failed\n");
		return -1;
	}

	/* get the ping queue */
	queue = odp_queue_lookup("ping_timer_queue");

	for (i = 0; i < PING_CNT; i++) {
		/* prepare icmp pkt */
		bzero(&pckt, sizeof(pckt));
		pckt.hdr.type = ICMP_ECHO;
		pckt.hdr.un.echo.id = pid;

		for (j = 0; j < sizeof(pckt.msg)-1; j++)
			pckt.msg[j] = j+'0';

		pckt.msg[j] = 0;
		pckt.hdr.un.echo.sequence = cnt++;
		pckt.hdr.checksum = odp_chksum(&pckt, sizeof(pckt));


		/* txmit the pkt */
		if (sendto(sd, &pckt, sizeof(pckt), 0,
			   (struct sockaddr *)addr, sizeof(*addr)) <= 0) {
			ODP_ERR("sendto operation failed msg_cnt [%d]..exiting sender thread\n", i);
			return -1;
		}
		printf(" icmp_sent msg_cnt %d\n", i);

		/* arm the timer */
		tick = odp_timer_current_tick(test_timer_ping);
		ODP_DBG("  [%i] current tick %"PRIu64"\n", thr, tick);

		tick += 1000;
		test_ping_tmo = odp_timer_absolute_tmo(test_timer_ping, tick,
							queue,
							ODP_BUFFER_INVALID);

		/* wait for timeout event */
		while ((buf = odp_queue_deq(queue) == ODP_BUFFER_INVALID)) {
			/* flag true means ack rxvd.. a cruel hack as I
			 * am confused on method to get away from while
			 * loop in case of ack rxvd..
			 * FIXME..
			 */
			if (ping_sync_flag) {
				ping_sync_flag = false;
				ODP_DBG(" [%d] done :)!!\n", i);
				buf = ODP_BUFFER_INVALID;
				break;
			}
		}

		/* free tmo_buf for timeout case */
		if (buf != ODP_BUFFER_INVALID) {
			ODP_DBG("  [%i] timeout msg_cnt [%i] (:-\n", thr, i);
			odp_buffer_free(buf);
		}
	}

	return 0;
}

static void *ping_timer_thread(void *arg)
{
	ping_arg_t *parg = (ping_arg_t *)arg;
	int thr;

	thr = odp_thread_id();

	printf("Ping thread %i starts\n", thr);

	switch (parg->thrdarg.testcase) {
	case ODP_TIMER_PING_TEST:
		if (thr == 1)
			if (send_ping_request(&dst_addr) < 0)
				parg->result = -1;
		if (thr == 2)
			if (listen_to_pingack() < 0)
				parg->result = -1;
		break;
	default:
		ODP_ERR("Invalid test case [%d]\n", parg->thrdarg.testcase);
	}

	fflush(stdout);

	return parg;
}

static int ping_init(int count, char *name[])
{
	struct hostent *hname;
	if (count != 2) {
		ODP_ERR("usage: %s <hostaddr>\n", name[0]);
		return -1;
	}

	if (count > 1) {
		pid = getpid();
		proto = getprotobyname("ICMP");
		hname = gethostbyname(name[1]);
		bzero(&dst_addr, sizeof(dst_addr));
		dst_addr.sin_family = hname->h_addrtype;
		dst_addr.sin_port = 0;
		dst_addr.sin_addr.s_addr = *(long *)hname->h_addr;
	}
	printf("ping to addr %s\n", name[1]);

	return 0;
}

int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	ping_arg_t pingarg;
	odp_queue_t queue;
	odp_buffer_pool_t pool;
	void *pool_base;

	if (odp_test_global_init() != 0)
		return -1;

	odp_print_system_info();

	if (ping_init(argc, argv) != 0)
		return -1;

	/*
	 * Create message pool
	 */
	pool_base = odp_shm_reserve("msg_pool",
					MSG_POOL_SIZE, ODP_CACHE_LINE_SIZE);

	pool = odp_buffer_pool_create("msg_pool", pool_base, MSG_POOL_SIZE,
					BUF_SIZE,
					ODP_CACHE_LINE_SIZE,
					ODP_BUFFER_TYPE_RAW);
	if (pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("Pool create failed.\n");
		return -1;
	}

	/*
	 * Create a queue for timer test
	 */
	queue = odp_queue_create("ping_timer_queue", ODP_QUEUE_TYPE_SCHED,
				 NULL);

	if (queue == ODP_QUEUE_INVALID) {
		ODP_ERR("Timer queue create failed.\n");
		return -1;
	}

	test_timer_ping = odp_timer_create("ping_timer", pool,
					   1000000, 1000000, 1000000000000);
	odp_shm_print_all();

	pingarg.thrdarg.testcase = ODP_TIMER_PING_TEST;
	pingarg.thrdarg.numthrds = odp_sys_core_count();

	pingarg.result = 0;

	/* Create and launch worker threads */
	odp_test_thread_create(ping_timer_thread, (pthrd_arg *)&pingarg);

	/* Wait for worker threads to exit */
	odp_test_thread_exit(&pingarg.thrdarg);

	ODP_DBG("ping timer test %s\n", (pingarg.result == 0) ? "passed" : "failed");

	printf("ODP ping timer test complete\n\n");

	return 0;
}
