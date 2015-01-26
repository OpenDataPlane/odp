/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <example_debug.h>

#include <odp.h>

#include <odph_eth.h>
#include <odph_ip.h>
#include <odph_icmp.h>

#include <odp_ipsec_stream.h>
#include <odp_ipsec_loop_db.h>

#define STREAM_MAGIC 0xBABE01234567CAFE

/**
 * Control use of odp_queue_deq versus odp_queue_deq_multi
 * when draining stream output queues
 *
 * @todo Make this command line driven versus compile time
 *       (see https://bugs.linaro.org/show_bug.cgi?id=626)
 */
#define LOOP_DEQ_MULTIPLE     0     /**< enable multi packet dequeue */
#define LOOP_DEQ_COUNT        32    /**< packets to dequeue at once */

/**
 * Stream packet header
 */
typedef struct ODP_PACKED stream_pkt_hdr_s {
	uint64be_t magic;    /**< Stream magic value for verification */
	uint8_t    data[0];  /**< Incrementing data stream */
} stream_pkt_hdr_t;

stream_db_t *stream_db;

void init_stream_db(void)
{
	odp_shm_t shm;

	shm = odp_shm_reserve("stream_db",
			      sizeof(stream_db_t),
			      ODP_CACHE_LINE_SIZE,
			      0);

	stream_db = odp_shm_addr(shm);

	if (stream_db == NULL) {
		EXAMPLE_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(stream_db, 0, sizeof(*stream_db));
}

int create_stream_db_entry(char *input)
{
	int pos = 0;
	char *local;
	char *str;
	char *save;
	char *token;
	stream_db_entry_t *entry = &stream_db->array[stream_db->index];

	/* Verify we have a good entry */
	if (MAX_DB <= stream_db->index)
		return -1;

	/* Make a local copy */
	local = malloc(strlen(input) + 1);
	if (NULL == local)
		return -1;
	strcpy(local, input);

	/* Setup for using "strtok_r" to search input string */
	str = local;
	save = NULL;

	/* Parse tokens separated by ':' */
	while (NULL != (token = strtok_r(str, ":", &save))) {
		str = NULL;  /* reset str for subsequent strtok_r calls */

		/* Parse token based on its position */
		switch (pos) {
		case 0:
			parse_ipv4_string(token, &entry->src_ip, NULL);
			break;
		case 1:
			parse_ipv4_string(token, &entry->dst_ip, NULL);
			break;
		case 2:
			entry->input.loop = loop_if_index(token);
			if (entry->input.loop < 0) {
				EXAMPLE_ERR("Error: stream must have input"
					    " loop\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 3:
			entry->output.loop = loop_if_index(token);
			break;
		case 4:
			entry->count = atoi(token);
			break;
		case 5:
			entry->length = atoi(token);
			if (entry->length < sizeof(stream_pkt_hdr_t))
				entry->length = 0;
			else
				entry->length -= sizeof(stream_pkt_hdr_t);
			break;
		default:
			printf("ERROR: extra token \"%s\" at position %d\n",
			       token, pos);
			break;
		}

		/* Advance to next position */
		pos++;
	}

	/* Verify we parsed exactly the number of tokens we expected */
	if (6 != pos) {
		printf("ERROR: \"%s\" contains %d tokens, expected 6\n",
		       input,
		       pos);
		free(local);
		return -1;
	}

	/* Add stream to the list */
	entry->id = stream_db->index++;
	entry->next = stream_db->list;
	stream_db->list = entry;

	free(local);
	return 0;
}

void resolve_stream_db(void)
{
	stream_db_entry_t *stream = NULL;

	/* For each stream look for input and output IPsec entries */
	for (stream = stream_db->list; NULL != stream; stream = stream->next) {
		ipsec_cache_entry_t *entry;

		/* Lookup input entry */
		entry = find_ipsec_cache_entry_in(stream->src_ip,
						  stream->dst_ip,
						  NULL,
						  NULL);
		stream->input.entry = entry;

		/* Lookup output entry */
		entry = find_ipsec_cache_entry_out(stream->src_ip,
						   stream->dst_ip,
						   0);
		stream->output.entry = entry;
	}
}

odp_packet_t create_ipv4_packet(stream_db_entry_t *stream,
				uint8_t *dmac,
				odp_buffer_pool_t pkt_pool)
{
	ipsec_cache_entry_t *entry = stream->input.entry;
	odp_packet_t pkt;
	uint8_t *base;
	uint8_t *data;
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	odph_ahhdr_t *ah = NULL;
	odph_esphdr_t *esp = NULL;
	odph_icmphdr_t *icmp;
	stream_pkt_hdr_t *test;
	uint i;

	/* Get packet */
	pkt = odp_packet_alloc(pkt_pool, 0);
	if (ODP_PACKET_INVALID == pkt)
		return ODP_PACKET_INVALID;
	base = odp_packet_data(pkt);
	data = odp_packet_data(pkt);

	/* Ethernet */
	odp_packet_has_eth_set(pkt, 1);
	odp_packet_l2_offset_set(pkt, data - base);
	eth = (odph_ethhdr_t *)data;
	data += sizeof(*eth);

	memset((char *)eth->src.addr, (0x80 | stream->id), ODPH_ETHADDR_LEN);
	memcpy((char *)eth->dst.addr, dmac, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);

	/* IPv4 */
	odp_packet_has_ipv4_set(pkt, 1);
	odp_packet_l3_offset_set(pkt, data - base);
	ip = (odph_ipv4hdr_t *)data;
	data += sizeof(*ip);
	odp_packet_l4_offset_set(pkt, data - base);

	/* Wait until almost finished to fill in mutable fields */
	memset((char *)ip, 0, sizeof(*ip));
	ip->ver_ihl = 0x45;
	ip->proto = ODPH_IPPROTO_ICMP;
	ip->id = odp_cpu_to_be_16(stream->id);
	ip->src_addr = odp_cpu_to_be_32(stream->src_ip);
	ip->dst_addr = odp_cpu_to_be_32(stream->dst_ip);

	/* AH (if specified) */
	if (entry && (ODP_AUTH_ALG_NULL != entry->ah.alg)) {
		if (ODP_AUTH_ALG_MD5_96 != entry->ah.alg)
			abort();

		ah = (odph_ahhdr_t *)data;
		data += sizeof(*ah);
		data += entry->ah.icv_len;

		memset((char *)ah, 0, sizeof(*ah) + entry->ah.icv_len);
		ah->ah_len = 1 + (entry->ah.icv_len / 4);
		ah->spi = odp_cpu_to_be_32(entry->ah.spi);
		ah->seq_no = odp_cpu_to_be_32(stream->input.ah_seq++);
	}

	/* ESP (if specified) */
	if (entry && (ODP_CIPHER_ALG_NULL != entry->esp.alg)) {
		if (ODP_CIPHER_ALG_3DES_CBC != entry->esp.alg)
			abort();

		esp = (odph_esphdr_t *)data;
		data += sizeof(*esp);
		data += entry->esp.iv_len;

		esp->spi = odp_cpu_to_be_32(entry->esp.spi);
		esp->seq_no = odp_cpu_to_be_32(stream->input.esp_seq++);
		RAND_bytes(esp->iv, 8);
	}

	/* ICMP header so we can see it on wireshark */
	icmp = (odph_icmphdr_t *)data;
	data += sizeof(*icmp);
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = odp_cpu_to_be_16(0x1234);
	icmp->un.echo.sequence = odp_cpu_to_be_16(stream->created);

	/* Packet payload of incrementing bytes */
	test = (stream_pkt_hdr_t *)data;
	data += sizeof(*test);
	test->magic = odp_cpu_to_be_64(STREAM_MAGIC);
	for (i = 0; i < stream->length; i++)
		*data++ = (uint8_t)i;

	/* Close ICMP */
	icmp->chksum = 0;
	icmp->chksum = odp_chksum(icmp, data - (uint8_t *)icmp);

	/* Close ESP if specified */
	if (esp) {
		int payload_len = data - (uint8_t *)icmp;
		int encrypt_len;
		odph_esptrl_t *esp_t;
		DES_key_schedule ks1, ks2, ks3;
		uint8_t iv[8];

		memcpy(iv, esp->iv, sizeof(iv));

		encrypt_len = ESP_ENCODE_LEN(payload_len + sizeof(*esp_t),
					     entry->esp.block_len);
		memset(data, 0, encrypt_len - payload_len);
		data += encrypt_len - payload_len;

		esp_t = (odph_esptrl_t *)(data) - 1;
		esp_t->pad_len = encrypt_len - payload_len - sizeof(*esp_t);
		esp_t->next_header = ip->proto;
		ip->proto = ODPH_IPPROTO_ESP;

		DES_set_key((DES_cblock *)&entry->esp.key.data[0], &ks1);
		DES_set_key((DES_cblock *)&entry->esp.key.data[8], &ks2);
		DES_set_key((DES_cblock *)&entry->esp.key.data[16], &ks3);

		DES_ede3_cbc_encrypt((uint8_t *)icmp,
				     (uint8_t *)icmp,
				     encrypt_len,
				     &ks1,
				     &ks2,
				     &ks3,
				     (DES_cblock *)iv,
				     1);
	}

	/* Since ESP can pad we can now fix IP length */
	ip->tot_len = odp_cpu_to_be_16(data - (uint8_t *)ip);
	odp_packet_push_tail(pkt, data - base);

	/* Close AH if specified */
	if (ah) {
		uint8_t hash[EVP_MAX_MD_SIZE];
		int auth_len = data - (uint8_t *)ip;

		ah->next_header = ip->proto;
		ip->proto = ODPH_IPPROTO_AH;

		HMAC(EVP_md5(),
		     entry->ah.key.data,
		     entry->ah.key.length,
		     (uint8_t *)ip,
		     auth_len,
		     hash,
		     NULL);

		memcpy(ah->icv, hash, 12);
	}

	/* Now fill in final IP header fields */
	ip->ttl = 64;
	ip->tos = 0;
	ip->frag_offset = 0;
	ip->chksum = 0;
	odph_ipv4_csum_update(pkt);
	return pkt;
}

bool verify_ipv4_packet(stream_db_entry_t *stream,
			odp_packet_t pkt)
{
	ipsec_cache_entry_t *entry = stream->output.entry;
	uint8_t *data;
	odph_ipv4hdr_t *ip;
	odph_ahhdr_t *ah = NULL;
	odph_esphdr_t *esp = NULL;
	int hdr_len;
	odph_icmphdr_t *icmp;
	stream_pkt_hdr_t *test;

	/* Basic IPv4 verify (add checksum verification) */
	data = odp_packet_l3_ptr(pkt, NULL);
	ip = (odph_ipv4hdr_t *)data;
	data += sizeof(*ip);
	if (0x45 != ip->ver_ihl)
		return FALSE;
	if (stream->src_ip != odp_be_to_cpu_32(ip->src_addr))
		return FALSE;
	if (stream->dst_ip != odp_be_to_cpu_32(ip->dst_addr))
		return FALSE;

	/* Find IPsec headers if any and compare against entry */
	hdr_len = locate_ipsec_headers(ip, &ah, &esp);
	if (ah) {
		if (!entry)
			return FALSE;
		if (ODP_AUTH_ALG_NULL == entry->ah.alg)
			return FALSE;
		if (odp_be_to_cpu_32(ah->spi) != entry->ah.spi)
			return FALSE;
		if (ODP_AUTH_ALG_MD5_96 != entry->ah.alg)
			abort();
	} else {
		if (entry && (ODP_AUTH_ALG_NULL != entry->ah.alg))
			return FALSE;
	}
	if (esp) {
		if (!entry)
			return FALSE;
		if (ODP_CIPHER_ALG_NULL == entry->esp.alg)
			return FALSE;
		if (odp_be_to_cpu_32(esp->spi) != entry->esp.spi)
			return FALSE;
		if (ODP_CIPHER_ALG_3DES_CBC != entry->esp.alg)
			abort();
		hdr_len += entry->esp.iv_len;
	} else {
		if (entry && (ODP_CIPHER_ALG_NULL != entry->esp.alg))
			return FALSE;
	}
	data += hdr_len;

	/* Verify authentication (if present) */
	if (ah) {
		uint8_t  ip_tos;
		uint8_t  ip_ttl;
		uint16_t ip_frag_offset;
		uint8_t  icv[12];
		uint8_t  hash[EVP_MAX_MD_SIZE];

		/* Save/clear mutable fields */
		ip_tos = ip->tos;
		ip_ttl = ip->ttl;
		ip_frag_offset = odp_be_to_cpu_16(ip->frag_offset);
		ip->tos = 0;
		ip->ttl = 0;
		ip->frag_offset = 0;
		ip->chksum = 0;
		memcpy(icv, ah->icv, 12);
		memset(ah->icv, 0, 12);

		/* Calculate HMAC and compare */
		HMAC(EVP_md5(),
		     entry->ah.key.data,
		     entry->ah.key.length,
		     (uint8_t *)ip,
		     odp_be_to_cpu_16(ip->tot_len),
		     hash,
		     NULL);

		if (0 != memcmp(icv, hash, sizeof(icv)))
			return FALSE;

		ip->proto = ah->next_header;
		ip->tos = ip_tos;
		ip->ttl = ip_ttl;
		ip->frag_offset = odp_cpu_to_be_16(ip_frag_offset);
	}

	/* Decipher if present */
	if (esp) {
		odph_esptrl_t *esp_t;
		DES_key_schedule ks1, ks2, ks3;
		uint8_t iv[8];
		int encrypt_len = ipv4_data_len(ip) - hdr_len;

		memcpy(iv, esp->iv, sizeof(iv));

		DES_set_key((DES_cblock *)&entry->esp.key.data[0], &ks1);
		DES_set_key((DES_cblock *)&entry->esp.key.data[8], &ks2);
		DES_set_key((DES_cblock *)&entry->esp.key.data[16], &ks3);

		DES_ede3_cbc_encrypt((uint8_t *)data,
				     (uint8_t *)data,
				     encrypt_len,
				     &ks1,
				     &ks2,
				     &ks3,
				     (DES_cblock *)iv,
				     0);

		esp_t = (odph_esptrl_t *)(data + encrypt_len) - 1;
		ip->proto = esp_t->next_header;
	}

	/* Verify ICMP packet */
	if (ODPH_IPPROTO_ICMP != ip->proto)
		return FALSE;

	/* Verify ICMP header */
	icmp = (odph_icmphdr_t *)data;
	data += sizeof(*icmp);
	if (ICMP_ECHO != icmp->type)
		return FALSE;
	if (0x1234 != odp_be_to_cpu_16(icmp->un.echo.id))
		return FALSE;

	/* Now check our packet */
	test = (stream_pkt_hdr_t *)data;
	if (STREAM_MAGIC != odp_be_to_cpu_64(test->magic))
		return FALSE;

	return TRUE;
}

int create_stream_db_inputs(void)
{
	int created = 0;
	odp_buffer_pool_t pkt_pool;
	stream_db_entry_t *stream = NULL;

	/* Lookup the packet pool */
	pkt_pool = odp_buffer_pool_lookup("packet_pool");
	if (pkt_pool == ODP_BUFFER_POOL_INVALID) {
		EXAMPLE_ERR("Error: pkt_pool not found\n");
		exit(EXIT_FAILURE);
	}

	/* For each stream create corresponding input packets */
	for (stream = stream_db->list; NULL != stream; stream = stream->next) {
		int count;
		uint8_t *dmac = query_loopback_db_mac(stream->input.loop);
		odp_queue_t queue = query_loopback_db_inq(stream->input.loop);

		for (count = stream->count; count > 0; count--) {
			odp_packet_t pkt;

			pkt = create_ipv4_packet(stream, dmac, pkt_pool);
			if (ODP_PACKET_INVALID == pkt) {
				printf("Packet buffers exhausted\n");
				break;
			}
			stream->created++;
			odp_queue_enq(queue, odp_packet_to_event(pkt));

			/* Count this stream when we create first packet */
			if (1 == stream->created)
				created++;
		}
	}

	return created;
}

bool verify_stream_db_outputs(void)
{
	bool done = TRUE;
	stream_db_entry_t *stream = NULL;

	/* For each stream look for output packets */
	for (stream = stream_db->list; NULL != stream; stream = stream->next) {
		int idx;
		int count;
		odp_queue_t queue;
		odp_buffer_t buf_tbl[LOOP_DEQ_COUNT];

		queue = query_loopback_db_outq(stream->output.loop);

		if (ODP_QUEUE_INVALID == queue)
			continue;

		for (;;) {
#if LOOP_DEQ_MULTIPLE
			count = odp_queue_deq_multi(queue,
						    buf_tbl,
						    LOOP_DEQ_COUNT);
#else
			odp_event_t ev;
			ev = odp_queue_deq(queue);
			buf_tbl[0] = odp_buffer_from_event(ev);
			count = (buf_tbl[0] != ODP_BUFFER_INVALID) ? 1 : 0;
#endif
			if (!count)
				break;
			for (idx = 0; idx < count; idx++) {
				bool good;
				odp_packet_t pkt;

				pkt = odp_packet_from_buffer(buf_tbl[idx]);

				good = verify_ipv4_packet(stream, pkt);
				if (good)
					stream->verified++;
				odp_packet_free(pkt);
			}
		}

		printf("Stream %d %d\n", stream->created, stream->verified);

		if (stream->created != stream->verified)
			done = FALSE;
	}
	return done;
}
