/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#define _POSIX_C_SOURCE 200809L

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>

#include <odp.h>
#include <odp/helper/odph_api.h>

/** @def SHM_PKT_POOL_SIZE
 * @brief Size of the shared memory block
 */
#define SHM_PKT_POOL_SIZE      8192

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE  100

/** @def MAX_PKT_BURST
 * @brief Maximum number of packet bursts
 */
#define MAX_PKT_BURST          16

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

#define TEST_SEQ_MAGIC		0x92749451
#define TEST_SEQ_MAGIC_2	0x81638340

#define TEST_ALLOC_MAGIC	0x1234adcd

#define TEST_IPC_PKTIO_NAME	"ipc:ipktio"
#define TEST_IPC_PKTIO_PID_NAME "ipc:%d:ipktio"

/** Can be any name, same or not the same. */
#define TEST_IPC_POOL_NAME "ipc_packet_pool"

/** magic number and sequence at start of packet payload */
typedef struct ODP_PACKED {
	odp_u32be_t magic;
	odp_u32be_t seq;
} pkt_head_t;

/** magic number at end of packet payload */
typedef struct ODP_PACKED {
	odp_u32be_t magic;
} pkt_tail_t;

/** Application argument */
char *pktio_name;

/** Run time in seconds */
int run_time_sec;

/** PID of the master process */
int master_pid;

/* helper funcs */
void parse_args(int argc, char *argv[]);
void print_info(char *progname);
void usage(char *progname);

/**
 * Create a ipc pktio handle.
 *
 * @param pool Pool to associate with device for packet RX/TX
 * @param master_pid Pid of master process
 *
 * @return The handle of the created pktio object.
 * @retval ODP_PKTIO_INVALID if the create fails.
 */
odp_pktio_t create_pktio(odp_pool_t pool, int master_pid);

/** Spin and send all packet from table
 *
 * @param pktio		pktio device
 * @param pkt_tbl	packets table
 * @param num		number of packets
 */
int ipc_odp_packet_send_or_free(odp_pktio_t pktio,
				odp_packet_t pkt_tbl[],
				int num);
