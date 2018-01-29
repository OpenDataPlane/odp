/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <protocols/eth.h>
#include <protocols/ip.h>
#include <odp/api/plat/packet_inlines.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <pthread.h>

#define PCAPNG_BLOCK_TYPE_EPB 0x00000006UL
#define PCAPNG_BLOCK_TYPE_SHB 0x0A0D0D0AUL
#define PCAPNG_BLOCK_TYPE_IDB 0x00000001UL
#define PCAPNG_ENDIAN_MAGIC 0x1A2B3C4DUL
#define PCAP_DATA_ALIGN (4)

/* inotify */
#define INOTIFY_EVENT_SIZE  (sizeof(struct inotify_event))
#define INOTIFY_BUF_LEN     (1024 * (INOTIFY_EVENT_SIZE + 16))
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
} pcapng_interface_description_block_s;

typedef struct pcapng_enhanced_packet_block_s {
	uint32_t block_type;
	uint32_t block_total_length;
	uint32_t interface_idx;
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	uint32_t captured_len;
	uint32_t packet_len;
} pcapng_enhanced_packet_block_t;

