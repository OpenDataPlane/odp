/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022-2023 Nokia
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include <errno.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <libconfig.h>

#define PROG_NAME "odp_ipsecfwd"
#define SHORT_PROG_NAME "ipsfwd"
#define DELIMITER ","

#define MIN(a, b)  (((a) <= (b)) ? (a) : (b))

#define MAX_IFS 2U
#define MAX_SAS 4000U
#define MAX_FWDS 64U
#define MAX_SPIS (UINT16_MAX + 1U)
#define MAX_WORKERS (ODP_THREAD_COUNT_MAX - 1)
#define MAX_QUEUES 64U
#define MAX_SA_QUEUES 1024U
#define PKT_SIZE 1024U
#define PKT_CNT 32768U
#define MAX_BURST 32U
#define ORDERED 0U

#define ALG_ENTRY(_alg_name, _type) \
	{ \
		.idx = (_alg_name), \
		.type = (_type), \
		.name = #_alg_name \
	}

enum {
	CIPHER_TYPE,
	COMB_CIPHER_TYPE,
	AUTH_TYPE,
	COMB_AUTH_TYPE
};

typedef enum {
	PRS_OK,
	PRS_NOK,
	PRS_TERM
} parse_result_t;

enum {
	DIR_IN = 0,
	DIR_OUT
};

typedef struct pktio_s pktio_t;

typedef struct pktio_s {
	union {
		odp_pktout_queue_t out_dir_qs[MAX_QUEUES];
		odp_queue_t out_ev_qs[MAX_QUEUES];
	};

	odp_pktin_queue_t in_dir_qs[MAX_QUEUES];
	odph_ethaddr_t src_mac;
	char *name;
	odp_pktio_t handle;
	uint32_t (*send_fn)(const pktio_t *pktio, uint8_t index, odp_packet_t pkts[], int num);
	uint32_t num_tx_qs;
	uint8_t idx;
} pktio_t;

typedef struct {
	odph_ethaddr_t dst_mac;
	const pktio_t *pktio;
	odph_iplookup_prefix_t prefix;
} fwd_entry_t;

typedef struct {
	uint64_t ipsec_in_pkts;
	uint64_t ipsec_out_pkts;
	uint64_t ipsec_in_errs;
	uint64_t ipsec_out_errs;
	uint64_t status_errs;
	uint64_t fwd_pkts;
	uint64_t discards;
} stats_t;

typedef struct prog_config_s prog_config_t;

typedef struct ODP_ALIGNED_CACHE {
	stats_t stats;
	prog_config_t *prog_config;
	int thr_idx;
	uint8_t pktio;
} thread_config_t;

typedef struct {
	odp_ipsec_sa_param_t sa_param;
	char cipher_key[65U];
	char cipher_key_extra[5U];
	char auth_key[65U];
	char auth_key_extra[5U];
	odp_u32be_t lkp_dst_ip;
	odp_u32be_t src_ip;
	odp_u32be_t dst_ip;
} sa_config_t;

typedef uint32_t (*rx_fn_t)(thread_config_t *config, odp_event_t evs[], int num);
typedef void (*ipsec_fn_t)(odp_packet_t pkts[], int num, odph_table_t fwd_tbl, stats_t *stats);
typedef void (*drain_fn_t)(prog_config_t *config);

typedef struct {
	rx_fn_t rx;
	ipsec_fn_t proc;
	ipsec_fn_t compl;
	drain_fn_t drain;
} ops_t;

typedef struct prog_config_s {
	odph_thread_t thread_tbl[MAX_WORKERS];
	thread_config_t thread_config[MAX_WORKERS];
	odp_ipsec_sa_t sas[MAX_SAS];
	fwd_entry_t fwd_entries[MAX_FWDS];
	odp_queue_t sa_qs[MAX_SA_QUEUES];
	pktio_t pktios[MAX_IFS];
	odp_atomic_u32_t is_running;
	sa_config_t default_cfg;
	ops_t ops;
	char *conf_file;
	odp_instance_t odp_instance;
	odp_queue_t compl_q;
	odp_pool_t pktio_pool;
	odph_table_t fwd_tbl;
	odp_barrier_t init_barrier;
	odp_barrier_t term_barrier;
	uint32_t num_input_qs;
	uint32_t num_sa_qs;
	uint32_t num_output_qs;
	uint32_t num_pkts;
	uint32_t pkt_len;
	uint32_t num_ifs;
	uint32_t num_sas;
	uint32_t num_fwds;
	int num_thrs;
	odp_bool_t is_dir_rx;
	odp_bool_t is_hashed_tx;
	uint8_t mode;
} prog_config_t;

typedef struct {
	const char *name;
	int idx;
	int type;
} exposed_alg_t;

typedef struct {
	odp_packet_t pkts[MAX_BURST];
	const pktio_t *pktio;
	uint32_t num;
} pkt_vec_t;

typedef struct {
	pkt_vec_t vecs[MAX_QUEUES];
	uint8_t num_qs;
} pkt_out_t;

typedef struct {
	pkt_out_t ifs[MAX_IFS];
	odp_bool_t is_hashed_tx;
	uint8_t q_idx;
} pkt_ifs_t;

static const exposed_alg_t exposed_algs[] = {
	ALG_ENTRY(ODP_CIPHER_ALG_NULL, CIPHER_TYPE),
	ALG_ENTRY(ODP_CIPHER_ALG_DES, CIPHER_TYPE),
	ALG_ENTRY(ODP_CIPHER_ALG_3DES_CBC, CIPHER_TYPE),
	ALG_ENTRY(ODP_CIPHER_ALG_AES_CBC, CIPHER_TYPE),
	ALG_ENTRY(ODP_CIPHER_ALG_AES_CTR, CIPHER_TYPE),
	ALG_ENTRY(ODP_CIPHER_ALG_AES_ECB, CIPHER_TYPE),
	ALG_ENTRY(ODP_CIPHER_ALG_AES_GCM, COMB_CIPHER_TYPE),
	ALG_ENTRY(ODP_CIPHER_ALG_AES_CCM, COMB_CIPHER_TYPE),
	ALG_ENTRY(ODP_CIPHER_ALG_CHACHA20_POLY1305, COMB_CIPHER_TYPE),
	ALG_ENTRY(ODP_AUTH_ALG_NULL, AUTH_TYPE),
	ALG_ENTRY(ODP_AUTH_ALG_MD5_HMAC, AUTH_TYPE),
	ALG_ENTRY(ODP_AUTH_ALG_SHA1_HMAC, AUTH_TYPE),
	ALG_ENTRY(ODP_AUTH_ALG_SHA224_HMAC, AUTH_TYPE),
	ALG_ENTRY(ODP_AUTH_ALG_SHA256_HMAC, AUTH_TYPE),
	ALG_ENTRY(ODP_AUTH_ALG_SHA384_HMAC, AUTH_TYPE),
	ALG_ENTRY(ODP_AUTH_ALG_SHA512_HMAC, AUTH_TYPE),
	ALG_ENTRY(ODP_AUTH_ALG_AES_GCM, COMB_AUTH_TYPE),
	ALG_ENTRY(ODP_AUTH_ALG_AES_GMAC, AUTH_TYPE),
	ALG_ENTRY(ODP_AUTH_ALG_AES_CCM, COMB_AUTH_TYPE),
	ALG_ENTRY(ODP_AUTH_ALG_AES_CMAC, AUTH_TYPE),
	ALG_ENTRY(ODP_AUTH_ALG_AES_XCBC_MAC, AUTH_TYPE),
	ALG_ENTRY(ODP_AUTH_ALG_CHACHA20_POLY1305, COMB_AUTH_TYPE)
};

/* SPIs for in and out directions */
static odp_ipsec_sa_t *spi_to_sa_map[2U][MAX_SPIS];
static const int ipsec_out_mark;
static __thread pkt_ifs_t ifs;
static prog_config_t *prog_conf;

static void init_config(prog_config_t *config)
{
	memset(config, 0, sizeof(*config));
	odp_ipsec_sa_param_init(&config->default_cfg.sa_param);
	config->compl_q = ODP_QUEUE_INVALID;
	config->pktio_pool = ODP_POOL_INVALID;
	config->num_input_qs = 1;
	config->num_sa_qs = 1;
	config->num_output_qs = 1;
	config->num_thrs = 1;
}

static void terminate(int signal ODP_UNUSED)
{
	odp_atomic_store_u32(&prog_conf->is_running, 0U);
}

static void parse_interfaces(prog_config_t *config, const char *optarg)
{
	char *tmp_str = strdup(optarg), *tmp;

	if (tmp_str == NULL)
		return;

	tmp = strtok(tmp_str, DELIMITER);

	while (tmp && config->num_ifs < MAX_IFS) {
		config->pktios[config->num_ifs].name = strdup(tmp);

		if (config->pktios[config->num_ifs].name != NULL)
			++config->num_ifs;

		tmp = strtok(NULL, DELIMITER);
	}

	free(tmp_str);
}

static void print_supported_algos(const odp_ipsec_capability_t *ipsec_capa)
{
	int c_cnt, a_cnt;
	const size_t len = sizeof(exposed_algs) / sizeof(exposed_algs[0]);

	printf("                          Cipher algorithms:\n");

	for (size_t i = 0U; i < len; ++i) {
		if ((exposed_algs[i].type == CIPHER_TYPE ||
		     exposed_algs[i].type == COMB_CIPHER_TYPE) &&
		    (ipsec_capa->ciphers.all_bits & (1 << exposed_algs[i].idx)) > 0U) {
			c_cnt = odp_ipsec_cipher_capability(exposed_algs[i].idx, NULL, 0);

			if (c_cnt < 0)
				continue;

			printf("                              %d: %s",
			       exposed_algs[i].idx, exposed_algs[i].name);
			printf(exposed_algs[i].type == COMB_CIPHER_TYPE ? " (combined)" : "");

			odp_ipsec_cipher_capability_t capa[c_cnt];

			(void)odp_ipsec_cipher_capability(exposed_algs[i].idx, capa, c_cnt);

			for (int j = 0; j < c_cnt; ++j)
				printf(j == 0 ? " (key lengths: %u" : ", %u", capa[j].key_len);

			printf(")\n");
		}
	}

	printf("                          Authentication algorithms:\n");

	for (size_t i = 0U; i < len; ++i) {
		if ((exposed_algs[i].type == AUTH_TYPE ||
		     exposed_algs[i].type == COMB_AUTH_TYPE) &&
		    (ipsec_capa->auths.all_bits & (1 << exposed_algs[i].idx)) > 0U) {
			a_cnt = odp_ipsec_auth_capability(exposed_algs[i].idx, NULL, 0);

			if (a_cnt < 0)
				continue;

			printf("                              %d: %s",
			       exposed_algs[i].idx, exposed_algs[i].name);
			printf(exposed_algs[i].type == COMB_AUTH_TYPE ? " (combined)" : "");

			odp_ipsec_auth_capability_t capa[a_cnt];

			(void)odp_ipsec_auth_capability(exposed_algs[i].idx, capa, a_cnt);

			for (int j = 0; j < a_cnt; ++j)
				printf(j == 0 ? " (key/icv lengths: %u/%u" : ", %u/%u",
				       capa[j].key_len, capa[j].icv_len);

			printf(")\n");
		}
	}
}

static void print_usage(void)
{
	odp_pool_capability_t pool_capa;
	odp_ipsec_capability_t ipsec_capa;

	if (odp_pool_capability(&pool_capa) < 0) {
		ODPH_ERR("Error querying pool capabilities\n");
		return;
	}

	if (odp_ipsec_capability(&ipsec_capa) < 0) {
		ODPH_ERR("Error querying IPsec capabilities\n");
		return;
	}

	printf("\n"
	       "Simple IPsec performance tester. Forward and process plain and IPsec packets.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "\n"
	       "  E.g. %s -i ens9f1 -C /etc/odp/ipsecfwd.conf\n"
	       "\n"
	       "  With ipsecfwd.conf containing, for example:\n"
	       "      default: {\n"
	       "          dir = 1\n"
	       "          proto = 0\n"
	       "          mode = 0\n"
	       "          crypto: {\n"
	       "              cipher_alg = 4\n"
	       "              cipher_key = \"jWnZr4t7w!zwC*F-\"\n"
	       "              auth_alg = 2\n"
	       "              auth_key = \"n2r5u7x!A%%D*\"\n"
	       "              icv_len = 12\n"
	       "          };\n"
	       "      };\n"
	       "\n"
	       "      sa: (\n"
	       "          {\n"
	       "              spi = 1337\n"
	       "              outbound: {\n"
	       "                  tunnel: {\n"
	       "                      src_addr = \"192.168.1.10\"\n"
	       "                      dst_addr = \"192.168.1.16\"\n"
	       "                  };\n"
	       "              };\n"
	       "          },\n"
	       "          {\n"
	       "              spi = 1338\n"
	       "              outbound: {\n"
	       "                  tunnel: {\n"
	       "                      src_addr = \"192.168.3.110\"\n"
	       "                      dst_addr = \"192.168.3.116\"\n"
	       "                  };\n"
	       "              };\n"
	       "          }\n"
	       "      );\n"
	       "\n"
	       "      fwd: (\n"
	       "          {\n"
	       "              prefix: \"192.168.1.0/24\"\n"
	       "              if: \"ens9f1\"\n"
	       "              dst_mac: \"00:00:05:00:07:00\"\n"
	       "          }\n"
	       "      );\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "\n"
	       "  -i, --interfaces    Ethernet interfaces for packet I/O, comma-separated,\n"
	       "                      no spaces.\n"
	       "  -C, --conf          Configuration file. 'libconfig' syntax is expected.\n"
	       "                      SA configuration supports default fallback, i.e.\n"
	       "                      individual SA configuration blocks may omit some\n"
	       "                      parameters and instead set these once in default block\n"
	       "                      which then are used to fill missing parameters. The only\n"
	       "                      required argument for an SA is the 'spi' parameter.\n"
	       "                      Individual SA parameter blocks are expected to be in\n"
	       "                      'sa'-named list. Parameter naming follows API\n"
	       "                      specification, see 'odp_ipsec_sa_param_t' for parameter\n"
	       "                      names and hierarchy. Traffic is mapped to SAs based on UDP\n"
	       "                      port: the port is used as the SPI. For forwarding entries,\n"
	       "                      individual parameter blocks are similarly expected to be\n"
	       "                      in 'fwd'-named list. With forwarding entries, every\n"
	       "                      parameter is always required and interfaces present in\n"
	       "                      forwarding entries should be one of the interfaces passed\n"
	       "                      with '--interfaces' option. See example above for\n"
	       "                      potential SA and forwarding configuration.\n"
	       "\n"
	       "                      Supported cipher and authentication algorithms for SAs:\n",
	       PROG_NAME, PROG_NAME);
	print_supported_algos(&ipsec_capa);
	printf("\n"
	       "Optional OPTIONS:\n"
	       "\n"
	       "  -n, --num_pkts      Number of packet buffers allocated for packet I/O pool.\n"
	       "                      %u by default.\n"
	       "  -l, --pkt_len       Maximum size of packet buffers in packet I/O pool. %u by\n"
	       "                      default.\n"
	       "  -c, --count         Worker thread count. 1 by default.\n"
	       "  -m, --mode          Queueing mode.\n"
	       "                          0: ordered (default)\n"
	       "                          1: parallel\n"
	       "  -I, --num_input_qs  Input queue count. 1 by default.\n"
	       "  -S, --num_sa_qs     SA queue count. 1 by default.\n"
	       "  -O, --num_output_qs Output queue count. 1 by default.\n"
	       "  -d, --direct_rx     Use direct RX. Interfaces will be polled by workers\n"
	       "                      directly. '--mode', '--num_input_qs' and '--num_output_qs'\n"
	       "                      options are ignored, input and output queue counts will\n"
	       "                      match worker count.\n"
	       "  -h, --help          This help.\n"
	       "\n", pool_capa.pkt.max_num > 0U ? MIN(pool_capa.pkt.max_num, PKT_CNT) : PKT_CNT,
	       pool_capa.pkt.max_len > 0U ? MIN(pool_capa.pkt.max_len, PKT_SIZE) : PKT_SIZE);
}

static inline odp_ipsec_sa_t *get_in_sa(odp_packet_t pkt)
{
	odph_esphdr_t esp;
	uint32_t spi;

	if (!odp_packet_has_ipsec(pkt))
		return NULL;

	if (odp_packet_copy_to_mem(pkt, odp_packet_l4_offset(pkt), ODPH_ESPHDR_LEN, &esp) < 0)
		return NULL;

	spi = odp_be_to_cpu_32(esp.spi);

	return spi <= UINT16_MAX ? spi_to_sa_map[DIR_IN][spi] : NULL;
}

static inline int process_ipsec_in_enq(odp_packet_t pkts[], const odp_ipsec_sa_t sas[], int num)
{
	odp_ipsec_in_param_t param;
	int left, sent = 0, ret;

	memset(&param, 0, sizeof(param));
	/* IPsec in/out need to be identified somehow, so use user_ptr for this. */
	for (int i = 0; i < num; ++i)
		odp_packet_user_ptr_set(pkts[i], NULL);

	while (sent < num) {
		left = num - sent;
		param.num_sa = left;
		param.sa = &sas[sent];
		ret = odp_ipsec_in_enq(&pkts[sent], left, &param);

		if (odp_unlikely(ret <= 0))
			break;

		sent += ret;
	}

	return sent;
}

static inline odp_ipsec_sa_t *get_out_sa(odp_packet_t pkt)
{
	odph_udphdr_t udp;
	uint16_t dst_port;

	if (!odp_packet_has_udp(pkt))
		return NULL;

	if (odp_packet_copy_to_mem(pkt, odp_packet_l4_offset(pkt), ODPH_UDPHDR_LEN, &udp) < 0)
		return NULL;

	dst_port = odp_be_to_cpu_16(udp.dst_port);

	return dst_port ? spi_to_sa_map[DIR_OUT][dst_port] : NULL;
}

static inline int process_ipsec_out_enq(odp_packet_t pkts[], const odp_ipsec_sa_t sas[], int num)
{
	odp_ipsec_out_param_t param;
	int left, sent = 0, ret;

	memset(&param, 0, sizeof(param));
	/* IPsec in/out need to be identified somehow, so use user_ptr for this. */
	for (int i = 0; i < num; ++i)
		odp_packet_user_ptr_set(pkts[i], &ipsec_out_mark);

	while (sent < num) {
		left = num - sent;
		param.num_sa = left;
		param.sa = &sas[sent];
		ret = odp_ipsec_out_enq(&pkts[sent], left, &param);

		if (odp_unlikely(ret <= 0))
			break;

		sent += ret;
	}

	return sent;
}

static inline const pktio_t *lookup_and_apply(odp_packet_t pkt, odph_table_t fwd_tbl,
					      uint8_t *q_idx)
{
	const uint32_t l3_off = odp_packet_l3_offset(pkt);
	odph_ipv4hdr_t ipv4;
	uint32_t dst_ip, src_ip;
	fwd_entry_t *fwd;
	odph_ethhdr_t eth;

	if (odp_packet_copy_to_mem(pkt, l3_off, ODPH_IPV4HDR_LEN, &ipv4) < 0)
		return NULL;

	dst_ip = odp_be_to_cpu_32(ipv4.dst_addr);

	if (odph_iplookup_table_get_value(fwd_tbl, &dst_ip, &fwd, 0U) < 0 || fwd == NULL)
		return NULL;

	if (l3_off != ODPH_ETHHDR_LEN) {
		if (l3_off > ODPH_ETHHDR_LEN) {
			if (odp_packet_pull_head(pkt, l3_off - ODPH_ETHHDR_LEN) == NULL)
				return NULL;
		} else {
			if (odp_packet_push_head(pkt, ODPH_ETHHDR_LEN - l3_off) == NULL)
				return NULL;
		}
	}

	eth.dst = fwd->dst_mac;
	eth.src = fwd->pktio->src_mac;
	eth.type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);

	if (odp_packet_copy_from_mem(pkt, 0U, ODPH_ETHHDR_LEN, &eth) < 0)
		return NULL;

	if (q_idx != NULL) {
		src_ip = odp_be_to_cpu_32(ipv4.src_addr);
		*q_idx = (src_ip ^ dst_ip) % fwd->pktio->num_tx_qs;
	}

	return fwd->pktio;
}

static inline uint32_t forward_packets(odp_packet_t pkts[], int num, odph_table_t fwd_tbl)
{
	odp_packet_t pkt;
	odp_bool_t is_hashed_tx = ifs.is_hashed_tx;
	uint8_t q_idx = is_hashed_tx ? 0U : ifs.q_idx, qs_done;
	uint8_t *q_idx_ptr = is_hashed_tx ? &q_idx : NULL;
	const pktio_t *pktio;
	pkt_out_t *out;
	pkt_vec_t *vec;
	uint32_t num_procd = 0U, ret;

	for (int i = 0; i < num; ++i) {
		pkt = pkts[i];
		pktio = lookup_and_apply(pkt, fwd_tbl, q_idx_ptr);

		if (pktio == NULL) {
			odp_packet_free(pkt);
			continue;
		}

		out = &ifs.ifs[pktio->idx];
		vec = &out->vecs[q_idx];

		if (vec->num == 0U)
			out->num_qs++;

		vec->pkts[vec->num++] = pkt;
		vec->pktio = pktio;
	}

	for (uint32_t i = 0U; i < MAX_IFS; ++i) {
		qs_done = 0U;
		out = &ifs.ifs[i];

		for (uint32_t j = 0U; j < MAX_QUEUES && qs_done < out->num_qs; ++j) {
			if (out->vecs[j].num == 0U)
				continue;

			vec = &out->vecs[j];
			pktio = vec->pktio;
			ret = pktio->send_fn(pktio, j, vec->pkts, vec->num);

			if (odp_unlikely(ret < vec->num))
				odp_packet_free_multi(&vec->pkts[ret], vec->num - ret);

			++qs_done;
			vec->num = 0U;
			num_procd += ret;
		}

		out->num_qs = 0U;
	}

	return num_procd;
}

static inline void process_packets_out_enq(odp_packet_t pkts[], int num, odph_table_t fwd_tbl,
					   stats_t *stats)
{
	odp_packet_t pkt, pkts_ips[MAX_BURST], pkts_fwd[MAX_BURST];
	odp_ipsec_sa_t *sa, sas[MAX_BURST];
	int num_pkts_ips = 0, num_pkts_fwd = 0, num_procd;

	for (int i = 0; i < num; ++i) {
		pkt = pkts[i];
		sa = get_out_sa(pkt);

		if (sa != NULL) {
			sas[num_pkts_ips] = *sa;
			pkts_ips[num_pkts_ips] = pkt;
			++num_pkts_ips;
		} else {
			pkts_fwd[num_pkts_fwd++] = pkt;
		}
	}

	if (num_pkts_ips > 0) {
		num_procd = process_ipsec_out_enq(pkts_ips, sas, num_pkts_ips);

		if (odp_unlikely(num_procd < num_pkts_ips)) {
			stats->ipsec_out_errs += num_pkts_ips - num_procd;
			odp_packet_free_multi(&pkts_ips[num_procd], num_pkts_ips - num_procd);
		}
	}

	if (num_pkts_fwd > 0) {
		num_procd = forward_packets(pkts_fwd, num_pkts_fwd, fwd_tbl);
		stats->discards += num_pkts_fwd - num_procd;
		stats->fwd_pkts += num_procd;
	}
}

static void process_packets_in_enq(odp_packet_t pkts[], int num, odph_table_t fwd_tbl,
				   stats_t *stats)
{
	odp_packet_t pkt, pkts_ips[MAX_BURST], pkts_out[MAX_BURST];
	odp_ipsec_sa_t *sa, sas[MAX_BURST];
	int num_pkts_ips = 0, num_pkts_out = 0, num_procd;

	for (int i = 0; i < num; ++i) {
		pkt = pkts[i];

		if (odp_unlikely(odp_packet_has_error(pkt))) {
			++stats->discards;
			odp_packet_free(pkt);
			continue;
		}

		sa = get_in_sa(pkt);

		if (sa != NULL) {
			sas[num_pkts_ips] = *sa;
			pkts_ips[num_pkts_ips] = pkt;
			++num_pkts_ips;
		} else {
			pkts_out[num_pkts_out++] = pkt;
		}
	}

	if (num_pkts_ips > 0) {
		num_procd = process_ipsec_in_enq(pkts_ips, sas, num_pkts_ips);

		if (odp_unlikely(num_procd < num_pkts_ips)) {
			stats->ipsec_in_errs += num_pkts_ips - num_procd;
			odp_packet_free_multi(&pkts_ips[num_procd], num_pkts_ips - num_procd);
		}
	}

	if (num_pkts_out > 0)
		process_packets_out_enq(pkts_out, num_pkts_out, fwd_tbl, stats);
}

static inline odp_bool_t is_ipsec_in(odp_packet_t pkt)
{
	return odp_packet_user_ptr(pkt) == NULL;
}

static void complete_ipsec_ops(odp_packet_t pkts[], int num, odph_table_t fwd_tbl, stats_t *stats)
{
	odp_packet_t pkt, pkts_out[MAX_BURST], pkts_fwd[MAX_BURST];
	odp_bool_t is_in;
	odp_ipsec_packet_result_t result;
	int num_pkts_out = 0, num_pkts_fwd = 0, num_procd;

	for (int i = 0; i < num; ++i) {
		pkt = pkts[i];
		is_in = is_ipsec_in(pkt);

		if (odp_unlikely(odp_ipsec_result(&result, pkt) < 0)) {
			is_in ? ++stats->ipsec_in_errs : ++stats->ipsec_out_errs;
			odp_packet_free(pkt);
			continue;
		}

		if (odp_unlikely(result.status.all != ODP_IPSEC_OK)) {
			is_in ? ++stats->ipsec_in_errs : ++stats->ipsec_out_errs;
			odp_packet_free(pkt);
			continue;
		}

		if (is_in) {
			++stats->ipsec_in_pkts;
			pkts_out[num_pkts_out++] = pkt;
		} else {
			++stats->ipsec_out_pkts;
			pkts_fwd[num_pkts_fwd++] = pkt;
		}
	}

	if (num_pkts_out > 0)
		process_packets_out_enq(pkts_out, num_pkts_out, fwd_tbl, stats);

	if (num_pkts_fwd > 0) {
		num_procd = forward_packets(pkts_fwd, num_pkts_fwd, fwd_tbl);
		stats->discards += num_pkts_fwd - num_procd;
		stats->fwd_pkts += num_procd;
	}
}

static void drain_scheduler(prog_config_t *config ODP_UNUSED)
{
	odp_event_t ev;

	while (true) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev == ODP_EVENT_INVALID)
			break;

		odp_event_free(ev);
	}
}

static inline int process_ipsec_in(odp_packet_t pkts[], const odp_ipsec_sa_t sas[], int num,
				   odp_packet_t pkts_out[])
{
	odp_ipsec_in_param_t param;
	int left, sent = 0, num_out, ret;

	memset(&param, 0, sizeof(param));

	while (sent < num) {
		left = num - sent;
		num_out = left;
		param.num_sa = left;
		param.sa = &sas[sent];
		ret = odp_ipsec_in(&pkts[sent], left, &pkts_out[sent], &num_out, &param);

		if (odp_unlikely(ret <= 0))
			break;

		sent += ret;
	}

	return sent;
}

static inline int process_ipsec_out(odp_packet_t pkts[], const odp_ipsec_sa_t sas[], int num,
				    odp_packet_t pkts_out[])
{
	odp_ipsec_out_param_t param;
	int left, sent = 0, num_out, ret;

	memset(&param, 0, sizeof(param));

	while (sent < num) {
		left = num - sent;
		num_out = left;
		param.num_sa = left;
		param.sa = &sas[sent];
		ret = odp_ipsec_out(&pkts[sent], left, &pkts_out[sent], &num_out, &param);

		if (odp_unlikely(ret <= 0))
			break;

		sent += ret;
	}

	return sent;
}

static inline void process_packets_out(odp_packet_t pkts[], int num, odph_table_t fwd_tbl,
				       stats_t *stats)
{
	odp_packet_t pkt, pkts_ips[MAX_BURST], pkts_fwd[MAX_BURST], pkts_ips_out[MAX_BURST];
	odp_ipsec_sa_t *sa, sas[MAX_BURST];
	int num_pkts_ips = 0, num_pkts_fwd = 0, num_procd;
	odp_ipsec_packet_result_t result;

	for (int i = 0; i < num; ++i) {
		pkt = pkts[i];
		sa = get_out_sa(pkt);

		if (sa != NULL) {
			sas[num_pkts_ips] = *sa;
			pkts_ips[num_pkts_ips] = pkt;
			++num_pkts_ips;
		} else {
			pkts_fwd[num_pkts_fwd++] = pkt;
		}
	}

	if (num_pkts_ips > 0) {
		num_procd = process_ipsec_out(pkts_ips, sas, num_pkts_ips, pkts_ips_out);

		if (odp_unlikely(num_procd < num_pkts_ips)) {
			stats->ipsec_out_errs += num_pkts_ips - num_procd;
			odp_packet_free_multi(&pkts_ips[num_procd], num_pkts_ips - num_procd);
		}

		for (int i = 0; i < num_procd; ++i) {
			pkt = pkts_ips_out[i];

			if (odp_unlikely(odp_ipsec_result(&result, pkt) < 0)) {
				++stats->ipsec_out_errs;
				odp_packet_free(pkt);
				continue;
			}

			if (odp_unlikely(result.status.all != ODP_IPSEC_OK)) {
				++stats->ipsec_out_errs;
				odp_packet_free(pkt);
				continue;
			}

			++stats->ipsec_out_pkts;
			pkts_fwd[num_pkts_fwd++] = pkt;
		}
	}

	if (num_pkts_fwd > 0) {
		num_procd = forward_packets(pkts_fwd, num_pkts_fwd, fwd_tbl);
		stats->discards += num_pkts_fwd - num_procd;
		stats->fwd_pkts += num_procd;
	}
}

static void process_packets_in(odp_packet_t pkts[], int num, odph_table_t fwd_tbl, stats_t *stats)
{
	odp_packet_t pkt, pkts_ips[MAX_BURST], pkts_out[MAX_BURST], pkts_ips_out[MAX_BURST];
	odp_ipsec_sa_t *sa, sas[MAX_BURST];
	int num_pkts_ips = 0, num_pkts_out = 0, num_procd;
	odp_ipsec_packet_result_t result;

	for (int i = 0; i < num; ++i) {
		pkt = pkts[i];

		if (odp_unlikely(odp_packet_has_error(pkt))) {
			++stats->discards;
			odp_packet_free(pkt);
			continue;
		}

		sa = get_in_sa(pkt);

		if (sa != NULL) {
			sas[num_pkts_ips] = *sa;
			pkts_ips[num_pkts_ips] = pkt;
			++num_pkts_ips;
		} else {
			pkts_out[num_pkts_out++] = pkt;
		}
	}

	if (num_pkts_ips > 0) {
		num_procd = process_ipsec_in(pkts_ips, sas, num_pkts_ips, pkts_ips_out);

		if (odp_unlikely(num_procd < num_pkts_ips)) {
			stats->ipsec_in_errs += num_pkts_ips - num_procd;
			odp_packet_free_multi(&pkts_ips[num_procd], num_pkts_ips - num_procd);
		}

		for (int i = 0; i < num_procd; ++i) {
			pkt = pkts_ips_out[i];

			if (odp_unlikely(odp_ipsec_result(&result, pkt) < 0)) {
				++stats->ipsec_in_errs;
				odp_packet_free(pkt);
				continue;
			}

			if (odp_unlikely(result.status.all != ODP_IPSEC_OK)) {
				++stats->ipsec_in_errs;
				odp_packet_free(pkt);
				continue;
			}

			++stats->ipsec_in_pkts;
			pkts_out[num_pkts_out++] = pkt;
		}
	}

	if (num_pkts_out > 0)
		process_packets_out(pkts_out, num_pkts_out, fwd_tbl, stats);
}

static void drain_direct_inputs(prog_config_t *config)
{
	odp_packet_t pkt;

	for (uint32_t i = 0U; i < config->num_ifs; ++i) {
		for (uint32_t j = 0U; j < config->num_input_qs; ++j) {
			while (odp_pktin_recv(config->pktios[i].in_dir_qs[j], &pkt, 1) == 1)
				odp_packet_free(pkt);
		}
	}
}

static odp_bool_t setup_ipsec(prog_config_t *config)
{
	odp_queue_param_t q_param;
	odp_ipsec_config_t ipsec_config;
	char q_name[ODP_QUEUE_NAME_LEN];

	if (!config->is_dir_rx) {
		snprintf(q_name, sizeof(q_name), SHORT_PROG_NAME "_sa_status");
		odp_queue_param_init(&q_param);
		q_param.type = ODP_QUEUE_TYPE_SCHED;
		q_param.sched.prio = odp_schedule_default_prio();
		q_param.sched.sync = ODP_SCHED_SYNC_PARALLEL;
		q_param.sched.group = ODP_SCHED_GROUP_ALL;
		config->compl_q = odp_queue_create(q_name, &q_param);

		if (config->compl_q == ODP_QUEUE_INVALID) {
			ODPH_ERR("Error creating IPsec completion queue\n");
			return false;
		}
	}

	odp_ipsec_config_init(&ipsec_config);

	if (!config->is_dir_rx) {
		ipsec_config.inbound_mode = ODP_IPSEC_OP_MODE_ASYNC;
		ipsec_config.outbound_mode = ODP_IPSEC_OP_MODE_ASYNC;
		config->ops.proc = process_packets_in_enq;
		config->ops.compl = complete_ipsec_ops;
		config->ops.drain = drain_scheduler;
	} else {
		ipsec_config.inbound_mode = ODP_IPSEC_OP_MODE_SYNC;
		ipsec_config.outbound_mode = ODP_IPSEC_OP_MODE_SYNC;
		config->ops.proc = process_packets_in;
		config->ops.compl = NULL;
		config->ops.drain = drain_direct_inputs;
	}

	ipsec_config.inbound.default_queue = config->compl_q;
	/* For tunnel to tunnel, we need to parse up to this to check the UDP port for SA. */
	ipsec_config.inbound.parse_level = ODP_PROTO_LAYER_L4;

	if (odp_ipsec_config(&ipsec_config) < 0) {
		ODPH_ERR("Error configuring IPsec\n");
		return false;
	}

	return true;
}

static odp_bool_t create_sa_dest_queues(odp_ipsec_capability_t *ipsec_capa,
					prog_config_t *config)
{
	odp_queue_param_t q_param;
	const uint32_t max_sa_qs = MIN(MAX_SA_QUEUES, ipsec_capa->max_queues);

	if (config->num_sa_qs == 0U || config->num_sa_qs > max_sa_qs) {
		ODPH_ERR("Invalid number of SA queues: %u (min: 1, max: %u)\n", config->num_sa_qs,
			 max_sa_qs);
		config->num_sa_qs = 0U;
		return false;
	}

	for (uint32_t i = 0U; i < config->num_sa_qs; ++i) {
		char q_name[ODP_QUEUE_NAME_LEN];

		snprintf(q_name, sizeof(q_name), SHORT_PROG_NAME "_sa_compl_%u", i);
		odp_queue_param_init(&q_param);
		q_param.type = ODP_QUEUE_TYPE_SCHED;
		q_param.sched.prio = odp_schedule_max_prio();
		q_param.sched.sync = config->mode == ORDERED ? ODP_SCHED_SYNC_ORDERED :
							       ODP_SCHED_SYNC_PARALLEL;
		q_param.sched.group = ODP_SCHED_GROUP_ALL;
		config->sa_qs[i] = odp_queue_create(q_name, &q_param);

		if (config->sa_qs[i] == ODP_QUEUE_INVALID) {
			ODPH_ERR("Error creating SA destination queue (created count: %u)\n", i);
			config->num_sa_qs = i;
			return false;
		}
	}

	return true;
}

static void parse_crypto(config_setting_t *cfg, sa_config_t *config)
{
	int val;
	const char *val_str;
	config_setting_t *cs = config_setting_lookup(cfg, "crypto");

	if (cs == NULL)
		return;

	if (config_setting_lookup_int(cs, "cipher_alg", &val) == CONFIG_TRUE)
		config->sa_param.crypto.cipher_alg = val;

	if (config_setting_lookup_string(cs, "cipher_key", &val_str) == CONFIG_TRUE) {
		strcpy(config->cipher_key, val_str);
		config->sa_param.crypto.cipher_key.data = (uint8_t *)config->cipher_key;
		config->sa_param.crypto.cipher_key.length =
			strlen((const char *)config->cipher_key);
	}

	if (config_setting_lookup_string(cs, "cipher_key_extra", &val_str) == CONFIG_TRUE) {
		strcpy(config->cipher_key_extra, val_str);
		config->sa_param.crypto.cipher_key_extra.data =
			(uint8_t *)config->cipher_key_extra;
		config->sa_param.crypto.cipher_key_extra.length =
			strlen((const char *)config->cipher_key_extra);
	}

	if (config_setting_lookup_int(cs, "auth_alg", &val) == CONFIG_TRUE)
		config->sa_param.crypto.auth_alg = val;

	if (config_setting_lookup_string(cs, "auth_key", &val_str) == CONFIG_TRUE) {
		strcpy(config->auth_key, val_str);
		config->sa_param.crypto.auth_key.data = (uint8_t *)config->auth_key;
		config->sa_param.crypto.auth_key.length = strlen((const char *)config->auth_key);
	}

	if (config_setting_lookup_string(cs, "auth_key_extra", &val_str) == CONFIG_TRUE) {
		strcpy(config->auth_key_extra, val_str);
		config->sa_param.crypto.auth_key_extra.data = (uint8_t *)config->auth_key_extra;
		config->sa_param.crypto.auth_key_extra.length =
			strlen((const char *)config->auth_key_extra);
	}

	if (config_setting_lookup_int(cs, "icv_len", &val) == CONFIG_TRUE)
		config->sa_param.crypto.icv_len = val;
}

static void parse_opt(config_setting_t *cfg, sa_config_t *config)
{
	int val;
	config_setting_t *cs = config_setting_lookup(cfg, "opt");

	if (cs == NULL)
		return;

	if (config_setting_lookup_int(cs, "esn", &val) == CONFIG_TRUE)
		config->sa_param.opt.esn = val;

	if (config_setting_lookup_int(cs, "udp_encap", &val) == CONFIG_TRUE)
		config->sa_param.opt.udp_encap = val;

	if (config_setting_lookup_int(cs, "copy_dscp", &val) == CONFIG_TRUE)
		config->sa_param.opt.copy_dscp = val;

	if (config_setting_lookup_int(cs, "copy_flabel", &val) == CONFIG_TRUE)
		config->sa_param.opt.copy_flabel = val;

	if (config_setting_lookup_int(cs, "copy_df", &val) == CONFIG_TRUE)
		config->sa_param.opt.copy_df = val;

	if (config_setting_lookup_int(cs, "dec_ttl", &val) == CONFIG_TRUE)
		config->sa_param.opt.dec_ttl = val;
}

static void parse_limits(config_setting_t *cfg, sa_config_t *config)
{
	config_setting_t *cs = config_setting_lookup(cfg, "lifetime"), *soft, *hard;
	long long val;

	if (cs == NULL)
		return;

	soft = config_setting_lookup(cs, "soft_limit");
	hard = config_setting_lookup(cs, "hard_limit");

	if (soft != NULL) {
		if (config_setting_lookup_int64(soft, "bytes", &val) == CONFIG_TRUE)
			config->sa_param.lifetime.soft_limit.bytes = val;

		if (config_setting_lookup_int64(soft, "packets", &val) == CONFIG_TRUE)
			config->sa_param.lifetime.soft_limit.packets = val;
	}

	if (hard != NULL) {
		if (config_setting_lookup_int64(hard, "bytes", &val) == CONFIG_TRUE)
			config->sa_param.lifetime.hard_limit.bytes = val;

		if (config_setting_lookup_int64(hard, "packets", &val) == CONFIG_TRUE)
			config->sa_param.lifetime.hard_limit.packets = val;
	}
}

static void parse_inbound(config_setting_t *cfg, sa_config_t *config)
{
	config_setting_t *cs = config_setting_lookup(cfg, "inbound");
	int val;
	const char *val_str;

	if (cs == NULL)
		return;

	if (config_setting_lookup_int(cs, "lookup_mode", &val) == CONFIG_TRUE)
		config->sa_param.inbound.lookup_mode = val;

	if (config_setting_lookup_string(cs, "lookup_dst_addr", &val_str) == CONFIG_TRUE) {
		if (odph_ipv4_addr_parse(&config->lkp_dst_ip, val_str) == 0) {
			config->lkp_dst_ip = odp_cpu_to_be_32(config->lkp_dst_ip);
			config->sa_param.inbound.lookup_param.dst_addr = &config->lkp_dst_ip;
		}
	}

	if (config_setting_lookup_int(cs, "antireplay_ws", &val) == CONFIG_TRUE)
		config->sa_param.inbound.antireplay_ws = val;

	if (config_setting_lookup_int(cs, "reassembly_en", &val) == CONFIG_TRUE)
		config->sa_param.inbound.reassembly_en = val;
}

static void parse_outbound(config_setting_t *cfg, sa_config_t *config)
{
	config_setting_t *cs = config_setting_lookup(cfg, "outbound"), *tunnel;
	const char *val_str;
	int val;

	if (cs == NULL)
		return;

	tunnel = config_setting_lookup(cs, "tunnel");

	if (tunnel != NULL) {
		if (config_setting_lookup_string(tunnel, "src_addr", &val_str) == CONFIG_TRUE) {
			if (odph_ipv4_addr_parse(&config->src_ip, val_str) == 0) {
				config->src_ip = odp_cpu_to_be_32(config->src_ip);
				config->sa_param.outbound.tunnel.ipv4.src_addr = &config->src_ip;
			}
		}

		if (config_setting_lookup_string(tunnel, "dst_addr", &val_str) == CONFIG_TRUE) {
			if (odph_ipv4_addr_parse(&config->dst_ip, val_str) == 0) {
				config->dst_ip = odp_cpu_to_be_32(config->dst_ip);
				config->sa_param.outbound.tunnel.ipv4.dst_addr = &config->dst_ip;
			}
		}

		if (config_setting_lookup_int(tunnel, "dscp", &val) == CONFIG_TRUE)
			config->sa_param.outbound.tunnel.ipv4.dscp = val;

		if (config_setting_lookup_int(tunnel, "df", &val) == CONFIG_TRUE)
			config->sa_param.outbound.tunnel.ipv4.df = val;

		if (config_setting_lookup_int(tunnel, "ttl", &val) == CONFIG_TRUE)
			config->sa_param.outbound.tunnel.ipv4.ttl = val;
	}

	if (config_setting_lookup_int(cs, "frag_mode", &val) == CONFIG_TRUE)
		config->sa_param.outbound.frag_mode = val;

	if (config_setting_lookup_int(cs, "mtu", &val) == CONFIG_TRUE)
		config->sa_param.outbound.mtu = val;
}

static void parse_sa_entry(config_setting_t *cfg, sa_config_t *config)
{
	int val;

	if (config_setting_lookup_int(cfg, "dir", &val) == CONFIG_TRUE)
		config->sa_param.dir = val;

	if (config_setting_lookup_int(cfg, "proto", &val) == CONFIG_TRUE)
		config->sa_param.proto = val;

	if (config_setting_lookup_int(cfg, "mode", &val) == CONFIG_TRUE)
		config->sa_param.mode = val;

	if (config_setting_lookup_int(cfg, "spi", &val) == CONFIG_TRUE)
		config->sa_param.spi = val;

	parse_crypto(cfg, config);
	parse_opt(cfg, config);
	parse_limits(cfg, config);
	parse_inbound(cfg, config);
	parse_outbound(cfg, config);
}

static void create_sa_entry(odp_ipsec_sa_param_t *sa_param, prog_config_t *config,
			    uint32_t max_num_sa)
{
	uint32_t dir = sa_param->dir;
	uint32_t spi = sa_param->spi;
	odp_ipsec_sa_t sa;

	if (config->num_sas == max_num_sa) {
		ODPH_ERR("Maximum number of SAs parsed (%u), ignoring rest\n", max_num_sa);
		return;
	}

	if (spi > UINT16_MAX) {
		ODPH_ERR("Unsupported SPI value for SA %u (> %u)\n", spi, UINT16_MAX);
		return;
	}

	if (spi_to_sa_map[dir][spi] != NULL) {
		ODPH_ERR("Non-unique SPIs not supported for SA %u\n", spi);
		return;
	}

	sa_param->dest_queue = config->sa_qs[config->num_sas % config->num_sa_qs];
	sa = odp_ipsec_sa_create(sa_param);

	if (sa == ODP_IPSEC_SA_INVALID) {
		ODPH_ERR("Error creating SA handle for SA %u\n", spi);
		return;
	}

	config->sas[config->num_sas] = sa;
	spi_to_sa_map[dir][spi] = &config->sas[config->num_sas];
	++config->num_sas;
}

static void parse_and_create_sa_entries(config_t *cfg, prog_config_t *config, uint32_t max_num_sa)
{
	config_setting_t *cs;
	int count;

	cs = config_lookup(cfg, "default");

	if (cs != NULL)
		parse_sa_entry(cs, &config->default_cfg);

	cs = config_lookup(cfg, "sa");

	if (cs == NULL)
		return;

	count = config_setting_length(cs);

	for (int i = 0; i < count; i++) {
		sa_config_t sa_cfg;
		config_setting_t *sa;
		int val;

		sa_cfg = config->default_cfg;
		sa = config_setting_get_elem(cs, i);

		if (sa == NULL)
			continue;

		if (config_setting_lookup_int(sa, "spi", &val) == CONFIG_TRUE) {
			parse_sa_entry(sa, &sa_cfg);
			create_sa_entry(&sa_cfg.sa_param, config, max_num_sa);
		}
	}
}

static void parse_sas(config_t *cfg, prog_config_t *config)
{
	odp_ipsec_capability_t ipsec_capa;
	uint32_t max_num_sa;

	if (odp_ipsec_capability(&ipsec_capa) < 0) {
		ODPH_ERR("Error querying IPsec capabilities\n");
		return;
	}

	if (!setup_ipsec(config))
		return;

	if (!config->is_dir_rx && !create_sa_dest_queues(&ipsec_capa, config))
		return;

	max_num_sa = MIN(MAX_SAS, ipsec_capa.max_num_sa);
	parse_and_create_sa_entries(cfg, config, max_num_sa);
}

static const pktio_t *get_pktio(const char *iface, const prog_config_t *config)
{
	for (uint32_t i = 0U; i < config->num_ifs; ++i) {
		if (strcmp(iface, config->pktios[i].name) == 0)
			return &config->pktios[i];
	}

	return NULL;
}

static void create_fwd_table_entry(config_setting_t *cfg, prog_config_t *config)
{
	const char *val_str;
	char dst_ip_str[16U] = { 0 };
	uint32_t mask, dst_ip;
	odph_ethaddr_t dst_mac;
	const pktio_t *pktio = NULL;
	fwd_entry_t *entry;
	odph_iplookup_prefix_t prefix;

	if (config->num_fwds == MAX_FWDS) {
		ODPH_ERR("Maximum number of forwarding entries parsed (%u), ignoring rest\n",
			 MAX_FWDS);
		return;
	}

	if (config_setting_lookup_string(cfg, "prefix", &val_str) == CONFIG_TRUE) {
		if (sscanf(val_str, "%[^/]/%u", dst_ip_str, &mask) != 2) {
			ODPH_ERR("Error parsing IP and subnet mask for forwarding entry\n");
			return;
		}

		if (odph_ipv4_addr_parse(&dst_ip, dst_ip_str) < 0) {
			ODPH_ERR("Syntax error in IP address for forwarding entry\n");
			return;
		}
	} else {
		return;
	}

	if (config_setting_lookup_string(cfg, "if", &val_str) == CONFIG_TRUE) {
		pktio = get_pktio(val_str, config);

		if (pktio == NULL) {
			ODPH_ERR("Error parsing next interface for forwarding entry\n");
			return;
		}
	} else {
		return;
	}

	if (config_setting_lookup_string(cfg, "dst_mac", &val_str) == CONFIG_TRUE) {
		if (odph_eth_addr_parse(&dst_mac, val_str) < 0) {
			ODPH_ERR("Syntax error in destination MAC for forwarding entry\n");
			return;
		}
	} else {
		return;
	}

	entry = &config->fwd_entries[config->num_fwds];
	entry->dst_mac = dst_mac;
	entry->pktio = pktio;
	prefix.ip = dst_ip;
	prefix.cidr = mask;
	entry->prefix = prefix;
	++config->num_fwds;
}

static void parse_fwd_table(config_t *cfg, prog_config_t *config)
{
	config_setting_t *cs;
	int count;

	cs = config_lookup(cfg, "fwd");

	if (cs == NULL)
		return;

	count = config_setting_length(cs);

	for (int i = 0; i < count; i++) {
		config_setting_t *fwd = config_setting_get_elem(cs, i);

		if (fwd == NULL)
			continue;

		create_fwd_table_entry(fwd, config);
	}
}

static parse_result_t check_options(prog_config_t *config)
{
	odp_pool_capability_t pool_capa;

	if (odp_pool_capability(&pool_capa) < 0) {
		ODPH_ERR("Error querying pool capabilities\n");
		return PRS_NOK;
	}

	if (config->num_ifs == 0U) {
		ODPH_ERR("Invalid number of interfaces: %u (min: 1, max: %u)\n", config->num_ifs,
			 MAX_IFS);
		return PRS_NOK;
	}

	if (config->num_fwds == 0U) {
		ODPH_ERR("Invalid number of forwarding entries: %u (min: 1, max: %u)\n",
			 config->num_fwds, MAX_FWDS);
		return PRS_NOK;
	}

	if (pool_capa.pkt.max_num > 0U && config->num_pkts > pool_capa.pkt.max_num) {
		ODPH_ERR("Invalid pool packet count: %u (max: %u)\n", config->num_pkts,
			 pool_capa.pkt.max_num);
		return PRS_NOK;
	}

	if (config->num_pkts == 0U)
		config->num_pkts = pool_capa.pkt.max_num > 0U ?
					MIN(pool_capa.pkt.max_num, PKT_CNT) : PKT_CNT;

	if (pool_capa.pkt.max_len > 0U && config->pkt_len > pool_capa.pkt.max_len) {
		ODPH_ERR("Invalid pool packet length: %u (max: %u)\n", config->pkt_len,
			 pool_capa.pkt.max_len);
		return PRS_NOK;
	}

	if (config->pkt_len == 0U)
		config->pkt_len = pool_capa.pkt.max_len > 0U ?
					MIN(pool_capa.pkt.max_len, PKT_SIZE) : PKT_SIZE;

	if (config->num_thrs <= 0 || config->num_thrs > MAX_WORKERS) {
		ODPH_ERR("Invalid thread count: %d (min: 1, max: %d)\n", config->num_thrs,
			 MAX_WORKERS);
		return PRS_NOK;
	}

	if (config->is_dir_rx) {
		config->num_input_qs = config->num_thrs;
		config->num_output_qs = config->num_thrs;
	}

	return PRS_OK;
}

static parse_result_t parse_options(int argc, char **argv, prog_config_t *config)
{
	int opt, long_index;
	config_t cfg;

	static const struct option longopts[] = {
		{ "interfaces", required_argument, NULL, 'i' },
		{ "num_pkts", required_argument, NULL, 'n' },
		{ "pkt_len", required_argument, NULL, 'l' },
		{ "count", required_argument, NULL, 'c' },
		{ "mode", required_argument, NULL, 'm' },
		{ "conf", required_argument, NULL, 'C' },
		{ "num_input_qs", required_argument, NULL, 'I' },
		{ "num_sa_qs", required_argument, NULL, 'S' },
		{ "num_output_qs", required_argument, NULL, 'O' },
		{ "direct_rx", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "i:n:l:c:m:C:I:S:O:dh";

	while (true) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'i':
			parse_interfaces(config, optarg);
			break;
		case 'n':
			config->num_pkts = atoi(optarg);
			break;
		case 'l':
			config->pkt_len = atoi(optarg);
			break;
		case 'c':
			config->num_thrs = atoi(optarg);
			break;
		case 'm':
			config->mode = !!atoi(optarg);
			break;
		case 'C':
			config->conf_file = strdup(optarg);
			break;
		case 'I':
			config->num_input_qs = atoi(optarg);
			break;
		case 'S':
			config->num_sa_qs = atoi(optarg);
			break;
		case 'O':
			config->num_output_qs = atoi(optarg);
			break;
		case 'd':
			config->is_dir_rx = true;
			break;
		case 'h':
			print_usage();
			return PRS_TERM;
		case '?':
		default:
			print_usage();
			return PRS_NOK;
		}
	}

	config_init(&cfg);

	if (config_read_file(&cfg, config->conf_file) == CONFIG_FALSE) {
		ODPH_ERR("Error opening SA configuration file: %s\n",  config_error_text(&cfg));
		config_destroy(&cfg);
		return PRS_NOK;
	}

	parse_sas(&cfg, config);
	parse_fwd_table(&cfg, config);
	config_destroy(&cfg);

	return check_options(config);
}

static parse_result_t setup_program(int argc, char **argv, prog_config_t *config)
{
	struct sigaction action = { .sa_handler = terminate };

	if (sigemptyset(&action.sa_mask) == -1 || sigaddset(&action.sa_mask, SIGINT) == -1 ||
	    sigaddset(&action.sa_mask, SIGTERM) == -1 ||
	    sigaddset(&action.sa_mask, SIGHUP) == -1 || sigaction(SIGINT, &action, NULL) == -1 ||
	    sigaction(SIGTERM, &action, NULL) == -1 || sigaction(SIGHUP, &action, NULL) == -1) {
		ODPH_ERR("Error installing signal handler\n");
		return PRS_NOK;
	}

	return parse_options(argc, argv, config);
}

static uint32_t schedule(thread_config_t *config ODP_UNUSED, odp_event_t evs[], int num)
{
	return odp_schedule_multi_no_wait(NULL, evs, num);
}

static uint32_t recv(thread_config_t *config, odp_event_t evs[], int num)
{
	prog_config_t *prog_config = config->prog_config;
	pktio_t *pktio = &prog_config->pktios[config->pktio++ % prog_config->num_ifs];
	odp_pktin_queue_t in_q = pktio->in_dir_qs[config->thr_idx % prog_config->num_input_qs];
	odp_packet_t pkts[num];
	int ret;

	ret = odp_pktin_recv(in_q, pkts, num);

	if (odp_unlikely(ret <= 0))
		return 0U;

	odp_packet_to_event_multi(pkts, evs, ret);

	return ret;
}

static uint32_t send(const pktio_t *pktio, uint8_t index, odp_packet_t pkts[], int num)
{
	int ret = odp_pktout_send(pktio->out_dir_qs[index], pkts, num);

	return ret < 0 ? 0U : (uint32_t)ret;
}

static uint32_t enqueue(const pktio_t *pktio, uint8_t index, odp_packet_t pkts[], int num)
{
	odp_event_t evs[MAX_BURST];
	int ret;

	odp_packet_to_event_multi(pkts, evs, num);

	ret = odp_queue_enq_multi(pktio->out_ev_qs[index], evs, num);

	return ret < 0 ? 0U : (uint32_t)ret;
}

static odp_bool_t setup_pktios(prog_config_t *config)
{
	odp_pool_param_t pool_param;
	pktio_t *pktio;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktio_capability_t capa;
	odp_pktout_queue_param_t pktout_param;
	odp_pktio_config_t pktio_config;
	uint32_t max_output_qs;

	odp_pool_param_init(&pool_param);
	pool_param.pkt.seg_len = config->pkt_len;
	pool_param.pkt.len = config->pkt_len;
	pool_param.pkt.num = config->num_pkts;
	pool_param.type = ODP_POOL_PACKET;
	config->pktio_pool = odp_pool_create(PROG_NAME, &pool_param);

	if (config->pktio_pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error creating packet I/O pool\n");
		return false;
	}

	config->ops.rx = !config->is_dir_rx ? schedule : recv;
	config->is_hashed_tx = !config->is_dir_rx && config->mode == ORDERED;

	for (uint32_t i = 0U; i < config->num_ifs; ++i) {
		pktio = &config->pktios[i];
		pktio->idx = i;
		odp_pktio_param_init(&pktio_param);
		pktio_param.in_mode = !config->is_dir_rx ?
			ODP_PKTIN_MODE_SCHED : ODP_PKTIN_MODE_DIRECT;
		pktio_param.out_mode = config->is_hashed_tx ?
			ODP_PKTOUT_MODE_QUEUE : ODP_PKTOUT_MODE_DIRECT;
		pktio->handle = odp_pktio_open(pktio->name, config->pktio_pool, &pktio_param);

		if (pktio->handle == ODP_PKTIO_INVALID) {
			ODPH_ERR("Error opening packet I/O (%s)\n", pktio->name);
			return false;
		}

		if (odp_pktio_capability(pktio->handle, &capa) < 0) {
			ODPH_ERR("Error querying packet I/O capabilities (%s)\n", pktio->name);
			return false;
		}

		if (config->num_input_qs == 0U || config->num_input_qs > capa.max_input_queues) {
			ODPH_ERR("Invalid number of input queues for packet I/O: %u (min: 1, max: "
				 "%u) (%s)\n", config->num_input_qs, capa.max_input_queues,
				 pktio->name);
			return false;
		}

		max_output_qs = MIN(MAX_QUEUES, capa.max_output_queues);

		if (config->num_output_qs == 0U || config->num_output_qs > max_output_qs) {
			ODPH_ERR("Invalid number of output queues for packet I/O: %u (min: 1, "
				 "max: %u) (%s)\n", config->num_output_qs, max_output_qs,
				 pktio->name);
			return false;
		}

		odp_pktin_queue_param_init(&pktin_param);

		if (config->is_hashed_tx)
			pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ORDERED;

		if (config->num_input_qs > 1U) {
			pktin_param.hash_enable = true;
			pktin_param.hash_proto.proto.ipv4_udp = 1U;
			pktin_param.num_queues = config->num_input_qs;
		}

		pktin_param.op_mode = (config->is_dir_rx &&
				       config->num_thrs > (int)config->num_input_qs) ?
						ODP_PKTIO_OP_MT : ODP_PKTIO_OP_MT_UNSAFE;

		if (odp_pktin_queue_config(pktio->handle, &pktin_param) < 0) {
			ODPH_ERR("Error configuring packet I/O input queues (%s)\n", pktio->name);
			return false;
		}

		if (config->is_dir_rx) {
			if (odp_pktin_queue(pktio->handle, pktio->in_dir_qs, config->num_input_qs)
			    != (int)config->num_input_qs) {
				ODPH_ERR("Error querying packet I/O input queue (%s)\n",
					 pktio->name);
				return false;
			}
		}

		pktio->send_fn = config->is_hashed_tx ? enqueue : send;
		pktio->num_tx_qs = config->num_output_qs;
		odp_pktout_queue_param_init(&pktout_param);
		pktout_param.num_queues = pktio->num_tx_qs;

		if (!config->is_hashed_tx) {
			pktout_param.op_mode = config->num_thrs > (int)pktio->num_tx_qs ?
				ODP_PKTIO_OP_MT : ODP_PKTIO_OP_MT_UNSAFE;
		}

		if (odp_pktout_queue_config(pktio->handle, &pktout_param) < 0) {
			ODPH_ERR("Error configuring packet I/O output queues (%s)\n", pktio->name);
			return false;
		}

		if (config->is_hashed_tx) {
			if (odp_pktout_event_queue(pktio->handle, pktio->out_ev_qs,
						   pktio->num_tx_qs) != (int)pktio->num_tx_qs) {
				ODPH_ERR("Error querying packet I/O output event queue (%s)\n",
					 pktio->name);
				return false;
			}
		} else {
			if (odp_pktout_queue(pktio->handle, pktio->out_dir_qs, pktio->num_tx_qs)
			    != (int)pktio->num_tx_qs) {
				ODPH_ERR("Error querying packet I/O output queue (%s)\n",
					 pktio->name);
				return false;
			}
		}

		odp_pktio_config_init(&pktio_config);

		if (odp_pktio_config(pktio->handle, &pktio_config) < 0) {
			ODPH_ERR("Error configuring packet I/O extra options (%s)\n", pktio->name);
			return false;
		}

		if (odp_pktio_mac_addr(pktio->handle, &pktio->src_mac, sizeof(pktio->src_mac))
		    != sizeof(pktio->src_mac)) {
			ODPH_ERR("Error getting packet I/O MAC address (%s)\n", pktio->name);
			return false;
		}

		if (odp_pktio_start(pktio->handle) < 0) {
			ODPH_ERR("Error starting packet I/O (%s)\n", pktio->name);
			return false;
		}
	}

	return true;
}

static odp_bool_t setup_fwd_table(prog_config_t *config)
{
	fwd_entry_t *fwd_e;

	config->fwd_tbl = odph_iplookup_table_create(SHORT_PROG_NAME "_fwd_tbl", 0U, 0U,
						     sizeof(fwd_entry_t *));

	if (config->fwd_tbl == NULL) {
		ODPH_ERR("Error creating forwarding table\n");
		return false;
	}

	for (uint32_t i = 0U; i < config->num_fwds; ++i) {
		fwd_e = &config->fwd_entries[i];

		if (odph_iplookup_table_put_value(config->fwd_tbl, &fwd_e->prefix, &fwd_e) < 0) {
			ODPH_ERR("Error populating forwarding table\n");
			return false;
		}
	}

	return true;
}

static inline void check_ipsec_status_ev(odp_event_t ev, stats_t *stats)
{
	odp_ipsec_status_t status;

	if (odp_unlikely(odp_ipsec_status(&status, ev) < 0 || status.result < 0))
		++stats->status_errs;

	odp_event_free(ev);
}

static int process_packets(void *args)
{
	thread_config_t *config = args;
	int thr_idx = odp_thread_id();
	odp_event_t evs[MAX_BURST], ev;
	ops_t ops = config->prog_config->ops;
	odp_atomic_u32_t *is_running = &config->prog_config->is_running;
	uint32_t cnt;
	odp_event_type_t type;
	odp_event_subtype_t subtype;
	odp_packet_t pkt, pkts_in[MAX_BURST], pkts_ips[MAX_BURST];
	odph_table_t fwd_tbl = config->prog_config->fwd_tbl;
	stats_t *stats = &config->stats;

	ifs.is_hashed_tx = config->prog_config->is_hashed_tx;
	ifs.q_idx = thr_idx % config->prog_config->num_output_qs;
	config->thr_idx = thr_idx;
	odp_barrier_wait(&config->prog_config->init_barrier);

	while (odp_atomic_load_u32(is_running)) {
		int num_pkts_in = 0, num_pkts_ips = 0;
		/* TODO: Add possibility to configure scheduler and ipsec enq/deq burst sizes. */
		cnt = ops.rx(config, evs, MAX_BURST);

		if (cnt == 0U)
			continue;

		for (uint32_t i = 0U; i < cnt; ++i) {
			ev = evs[i];
			type = odp_event_types(ev, &subtype);
			pkt = odp_packet_from_event(ev);

			if (type == ODP_EVENT_PACKET) {
				if (subtype == ODP_EVENT_PACKET_BASIC) {
					pkts_in[num_pkts_in++] = pkt;
				} else if (subtype == ODP_EVENT_PACKET_IPSEC) {
					pkts_ips[num_pkts_ips++] = pkt;
				} else {
					++stats->discards;
					odp_event_free(ev);
				}
			} else if (type == ODP_EVENT_IPSEC_STATUS) {
				check_ipsec_status_ev(ev, stats);
			} else {
				++stats->discards;
				odp_event_free(ev);
			}
		}

		if (num_pkts_in > 0)
			ops.proc(pkts_in, num_pkts_in, fwd_tbl, stats);

		if (ops.compl && num_pkts_ips > 0)
			ops.compl(pkts_ips, num_pkts_ips, fwd_tbl, stats);
	}

	odp_barrier_wait(&config->prog_config->term_barrier);
	ops.drain(config->prog_config);

	return 0;
}

static odp_bool_t setup_workers(prog_config_t *config)
{
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param[config->num_thrs];
	odp_cpumask_t cpumask;
	int num_workers;

	num_workers = odp_cpumask_default_worker(&cpumask, config->num_thrs);
	odph_thread_common_param_init(&thr_common);
	thr_common.instance = config->odp_instance;
	thr_common.cpumask = &cpumask;

	for (int i = 0; i < config->num_thrs; ++i) {
		odph_thread_param_init(&thr_param[i]);
		thr_param[i].start = process_packets;
		thr_param[i].thr_type = ODP_THREAD_WORKER;
		config->thread_config[i].prog_config = config;
		thr_param[i].arg = &config->thread_config[i];
	}

	num_workers = odph_thread_create(config->thread_tbl, &thr_common, thr_param, num_workers);

	if (num_workers != config->num_thrs) {
		ODPH_ERR("Error configuring worker threads\n");
		return false;
	}

	return true;
}

static odp_bool_t setup_test(prog_config_t *config)
{
	odp_barrier_init(&config->init_barrier, config->num_thrs + 1);
	odp_barrier_init(&config->term_barrier, config->num_thrs + 1);

	if (!setup_pktios(config))
		return false;

	if (!setup_fwd_table(config))
		return false;

	if (!setup_workers(config))
		return false;

	odp_barrier_wait(&config->init_barrier);

	return true;
}

static void stop_test(prog_config_t *config)
{
	for (uint32_t i = 0U; i < config->num_ifs; ++i)
		if (config->pktios[i].handle != ODP_PKTIO_INVALID)
			(void)odp_pktio_stop(config->pktios[i].handle);

	odp_barrier_wait(&config->term_barrier);
	(void)odph_thread_join(config->thread_tbl, config->num_thrs);
}

static void print_stats(const prog_config_t *config)
{
	const stats_t *stats;

	printf("\n====================\n\n"
	       "IPsec forwarder done\n\n"
	       "    configuration file: %s\n"
	       "    queuing mode:       %s\n"
	       "    input queue count:  %u\n"
	       "    SA queue count:     %u\n"
	       "    output queue count: %u\n"
	       "    RX mode:            %s\n", config->conf_file,
	       config->mode == ORDERED ? "ordered" : "parallel", config->num_input_qs,
	       config->num_sa_qs, config->num_output_qs,
	       config->is_dir_rx ? "direct" : "scheduled");

	for (int i = 0; i < config->num_thrs; ++i) {
		stats = &config->thread_config[i].stats;

		printf("\n    worker %d:\n"
		"        IPsec in packets:        %" PRIu64 "\n"
		"        IPsec out packets:       %" PRIu64 "\n"
		"        IPsec in packet errors:  %" PRIu64 "\n"
		"        IPsec out packet errors: %" PRIu64 "\n"
		"        IPsec status errors:     %" PRIu64 "\n"
		"        packets forwarded:       %" PRIu64 "\n"
		"        packets dropped:         %" PRIu64 "\n", i, stats->ipsec_in_pkts,
		stats->ipsec_out_pkts, stats->ipsec_in_errs, stats->ipsec_out_errs,
		stats->status_errs, stats->fwd_pkts, stats->discards);
	}

	printf("\n====================\n");
}

static void wait_sas_disabled(uint32_t num_sas)
{
	uint32_t num_sas_dis = 0U;
	odp_event_t ev;
	odp_ipsec_status_t status;

	while (num_sas_dis < num_sas) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev == ODP_EVENT_INVALID)
			continue;

		if (odp_event_type(ev) != ODP_EVENT_IPSEC_STATUS) {
			odp_event_free(ev);
			continue;
		}

		if (odp_ipsec_status(&status, ev) < 0) {
			odp_event_free(ev);
			continue;
		}

		if (status.id == ODP_IPSEC_STATUS_SA_DISABLE)
			++num_sas_dis;

		odp_event_free(ev);
	}
}

static void teardown_test(const prog_config_t *config)
{
	(void)odph_iplookup_table_destroy(config->fwd_tbl);

	for (uint32_t i = 0U; i < config->num_ifs; ++i)
		if (config->pktios[i].handle != ODP_PKTIO_INVALID) {
			(void)odp_pktio_close(config->pktios[i].handle);
			free(config->pktios[i].name);
		}

	if (config->pktio_pool != ODP_POOL_INVALID)
		(void)odp_pool_destroy(config->pktio_pool);

	for (uint32_t i = 0U; i < config->num_sas; ++i)
		(void)odp_ipsec_sa_disable(config->sas[i]);

	if (!config->is_dir_rx)
		/* Drain SA status events. */
		wait_sas_disabled(config->num_sas);

	for (uint32_t i = 0U; i < config->num_sas; ++i)
		(void)odp_ipsec_sa_destroy(config->sas[i]);

	for (uint32_t i = 0U; i < config->num_sa_qs; ++i)
		(void)odp_queue_destroy(config->sa_qs[i]);

	if (config->compl_q != ODP_QUEUE_INVALID)
		(void)odp_queue_destroy(config->compl_q);

	free(config->conf_file);
}

int main(int argc, char **argv)
{
	odph_helper_options_t odph_opts;
	odp_init_t init_param;
	odp_instance_t odp_instance;
	odp_shm_t shm_cfg = ODP_SHM_INVALID;
	parse_result_t parse_res;
	int ret = EXIT_SUCCESS;

	argc = odph_parse_options(argc, argv);

	if (odph_options(&odph_opts) == -1) {
		ODPH_ERR("Error while reading ODP helper options, exiting\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = odph_opts.mem_model;

	if (odp_init_global(&odp_instance, &init_param, NULL) < 0) {
		ODPH_ERR("ODP global init failed, exiting\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(odp_instance, ODP_THREAD_CONTROL) < 0) {
		ODPH_ERR("ODP local init failed, exiting\n");
		exit(EXIT_FAILURE);
	}

	shm_cfg = odp_shm_reserve(PROG_NAME "_cfg", sizeof(prog_config_t), ODP_CACHE_LINE_SIZE,
				  0U);

	if (shm_cfg == ODP_SHM_INVALID) {
		ODPH_ERR("Error reserving shared memory\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	prog_conf = odp_shm_addr(shm_cfg);

	if (prog_conf == NULL) {
		ODPH_ERR("Error resolving shared memory address\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	init_config(prog_conf);

	if (!prog_conf->is_dir_rx && odp_schedule_config(NULL) < 0) {
		ODPH_ERR("Error configuring scheduler\n");
		ret = EXIT_FAILURE;
		goto out_test;
	}

	parse_res = setup_program(argc, argv, prog_conf);

	if (parse_res == PRS_NOK) {
		ret = EXIT_FAILURE;
		goto out_test;
	}

	if (parse_res == PRS_TERM) {
		ret = EXIT_SUCCESS;
		goto out_test;
	}

	prog_conf->odp_instance = odp_instance;
	odp_atomic_init_u32(&prog_conf->is_running, 1U);

	if (!setup_test(prog_conf)) {
		ret = EXIT_FAILURE;
		goto out_test;
	}

	while (odp_atomic_load_u32(&prog_conf->is_running))
		odp_cpu_pause();

	stop_test(prog_conf);
	print_stats(prog_conf);

out_test:
	teardown_test(prog_conf);

out:
	if (shm_cfg != ODP_SHM_INVALID)
		(void)odp_shm_free(shm_cfg);

	if (odp_term_local() < 0) {
		ODPH_ERR("ODP local terminate failed, exiting\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(odp_instance) < 0) {
		ODPH_ERR("ODP global terminate failed, exiting\n");
		exit(EXIT_FAILURE);
	}

	return ret;
}
