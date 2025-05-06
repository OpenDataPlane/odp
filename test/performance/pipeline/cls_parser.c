/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libconfig.h>
#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "common.h"
#include "config_parser.h"

#define CONF_STR_COS "cos"
#define CONF_STR_PMR "pmr"
#define CONF_STR_PARSE_TEMPLATE "template"
#define CONF_STR_NAME "name"
#define CONF_STR_ACTION "action"
#define CONF_STR_NUM_QS "num_queues"
#define CONF_STR_QUEUE "queue"
#define CONF_STR_TYPE "type"
#define CONF_STR_HASH_IPV4_UDP "hash_ipv4_udp"
#define CONF_STR_HASH_IPV4_TCP "hash_ipv4_tcp"
#define CONF_STR_HASH_IPV4 "hash_ipv4"
#define CONF_STR_HASH_IPV6_UDP "hash_ipv6_udp"
#define CONF_STR_HASH_IPV6_TCP "hash_ipv6_tcp"
#define CONF_STR_HASH_IPV6 "hash_ipv6"
#define CONF_STR_POOL "pool"
#define CONF_STR_DEFAULT "default"
#define CONF_STR_PREFIX "prefix"
#define CONF_STR_IDX "start_index"
#define CONF_STR_INC "index_increment"
#define CONF_STR_SRC_COS "src_cos"
#define CONF_STR_DST_COS "dst_cos"
#define CONF_STR_TERM "term"
#define CONF_STR_MATCH_VALUE "match_value"
#define CONF_STR_MATCH_MASK "match_mask"
#define CONF_STR_VAL_SZ "val_sz"
#define CONF_STR_OFFSET "offset"

#define DROP "drop"
#define ENQUEUE "enqueue"
#define PLAIN "plain"
#define SCHEDULED "schedule"
#define LEN "len"
#define ETH_0 "eth_0"
#define ETH_X "eth_x"
#define VLAN_0 "vlan_0"
#define VLAN_X "vlan_x"
#define VLAN_PCP "vlan_pcp"
#define DMAC "dmac"
#define IPPROTO "ipproto"
#define IP_DSCP "ip_dscp"
#define UDP_DPORT "udp_dport"
#define TCP_DPORT "tcp_dport"
#define UDP_SPORT "udp_sport"
#define TCP_SPORT "tcp_sport"
#define SIP_ADDR "sip_addr"
#define DIP_ADDR "dip_addr"
#define SIP6_ADDR "sip6_addr"
#define DIP6_ADDR "dip6_addr"
#define IPSEC_SPI "ipsec_spi"
#define LD_VNI "ld_vni"
#define CUSTOM_FRAME "custom_frame"
#define CUSTOM_L3 "custom_l3"
#define SCTP_SPORT "sctp_sport"
#define SCTP_DPORT "sctp_dport"

typedef struct {
	char *name;
	char *queue;
	char *pool;
	char *def;
	odp_cls_cos_param_t cos_param;
	odp_queue_param_t q_param;
	odp_cos_t cos;
	odp_pktio_t def_pktio;
} cos_parse_t;

typedef struct {
	char *name;
	char *src;
	char *dst;
	uint8_t *val_arr;
	uint8_t *mask_arr;
	odp_pmr_param_t param;
	odp_pmr_t pmr;
} pmr_parse_t;

typedef struct {
	cos_parse_t *coss;
	pmr_parse_t *pmrs;
	uint32_t num_cos;
	uint32_t num_pmr;
} cls_parses_t;

typedef struct {
	char *name_prefix;
	char *action;
	char *queue_prefix;
	char *type;
	char *pool;
	uint32_t name_idx;
	uint32_t name_inc;
	uint32_t queue_idx;
	uint32_t queue_inc;
	uint32_t num_qs;
	uint32_t h_ipv4_udp;
	uint32_t h_ipv4_tcp;
	uint32_t h_ipv4;
	uint32_t h_ipv6_udp;
	uint32_t h_ipv6_tcp;
	uint32_t h_ipv6;
} cos_parse_template_t;

typedef struct {
	char *name_prefix;
	char *src_prefix;
	char *dst_prefix;
	char *term;
	uint8_t *val_arr;
	uint8_t *mask_arr;
	uint32_t name_idx;
	uint32_t name_inc;
	uint32_t src_idx;
	uint32_t src_inc;
	uint32_t dst_idx;
	uint32_t dst_inc;
	uint32_t val_arr_inc;
	uint32_t val_sz;
	uint32_t offset;
} pmr_parse_template_t;

typedef enum {
	PARSE_OK,
	PARSE_TEMPL,
	PARSE_NOK
} res_t;

static cls_parses_t cls;

static res_t parse_cos_entry(config_setting_t *cs, cos_parse_t *cos)
{
	const char *val_str;
	int val_i;

	if (config_setting_lookup(cs, CONF_STR_PARSE_TEMPLATE) != NULL)
		return PARSE_TEMPL;

	memset(cos, 0, sizeof(*cos));
	cos->cos = ODP_COS_INVALID;
	cos->def_pktio = ODP_PKTIO_INVALID;
	odp_cls_cos_param_init(&cos->cos_param);
	cos->cos_param.hash_proto.all_bits = 0U;
	odp_queue_param_init(&cos->q_param);

	if (config_setting_lookup_string(cs, CONF_STR_NAME, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return PARSE_NOK;
	}

	cos->name = strdup(val_str);

	if (cos->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (config_setting_lookup_string(cs, CONF_STR_ACTION, &val_str) == CONFIG_TRUE) {
		if (strcmp(val_str, DROP) == 0) {
			cos->cos_param.action = ODP_COS_ACTION_DROP;
		} else if (strcmp(val_str, ENQUEUE) == 0) {
			cos->cos_param.action = ODP_COS_ACTION_ENQUEUE;
		} else {
			ODPH_ERR("No valid \"" CONF_STR_ACTION "\" found\n");
			return PARSE_NOK;
		}
	}

	if (config_setting_lookup_string(cs, CONF_STR_DEFAULT, &val_str) == CONFIG_TRUE) {
		cos->def = strdup(val_str);

		if (cos->def == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	}

	if (cos->cos_param.action == ODP_COS_ACTION_DROP)
		return PARSE_OK;

	if (config_setting_lookup_int(cs, CONF_STR_NUM_QS, &val_i) == CONFIG_TRUE)
		cos->cos_param.num_queue = val_i;

	if (cos->cos_param.num_queue == 1U) {
		if (config_setting_lookup_string(cs, CONF_STR_QUEUE, &val_str) == CONFIG_FALSE) {
			ODPH_ERR("No \"" CONF_STR_QUEUE "\" found\n");
			return PARSE_NOK;
		}

		cos->queue = strdup(val_str);

		if (cos->queue == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	} else {
		if (config_setting_lookup_string(cs, CONF_STR_TYPE, &val_str) == CONFIG_TRUE) {
			if (strcmp(val_str, PLAIN) == 0) {
				cos->q_param.type = ODP_QUEUE_TYPE_PLAIN;
			} else if (strcmp(val_str, SCHEDULED) == 0) {
				cos->q_param.type = ODP_QUEUE_TYPE_SCHED;
			} else {
				ODPH_ERR("No valid \"" CONF_STR_TYPE "\" found\n");
				return PARSE_NOK;
			}
		}

		if (config_setting_lookup_int(cs, CONF_STR_HASH_IPV4_UDP, &val_i) == CONFIG_TRUE)
			cos->cos_param.hash_proto.proto.ipv4_udp = val_i;

		if (config_setting_lookup_int(cs, CONF_STR_HASH_IPV4_TCP, &val_i) == CONFIG_TRUE)
			cos->cos_param.hash_proto.proto.ipv4_tcp = val_i;

		if (config_setting_lookup_int(cs, CONF_STR_HASH_IPV4, &val_i) == CONFIG_TRUE)
			cos->cos_param.hash_proto.proto.ipv4 = val_i;

		if (config_setting_lookup_int(cs, CONF_STR_HASH_IPV6_UDP, &val_i) == CONFIG_TRUE)
			cos->cos_param.hash_proto.proto.ipv6_udp = val_i;

		if (config_setting_lookup_int(cs, CONF_STR_HASH_IPV6_TCP, &val_i) == CONFIG_TRUE)
			cos->cos_param.hash_proto.proto.ipv6_tcp = val_i;

		if (config_setting_lookup_int(cs, CONF_STR_HASH_IPV6, &val_i) == CONFIG_TRUE)
			cos->cos_param.hash_proto.proto.ipv6 = val_i;
	}

	if (config_setting_lookup_string(cs, CONF_STR_POOL, &val_str) == CONFIG_TRUE) {
		cos->pool = strdup(val_str);

		if (cos->pool == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	}

	return PARSE_OK;
}

static int parse_cos_entry_template(config_setting_t *cs, cos_parse_template_t *templ)
{
	int val_i;
	uint32_t num;
	config_setting_t *elem;
	const char *val_str;

	memset(templ, 0, sizeof(*templ));

	if (config_setting_lookup_int(cs, CONF_STR_PARSE_TEMPLATE, &val_i) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_PARSE_TEMPLATE "\" found\n");
		return -1;
	}

	num = val_i;

	if (num == 0U)
		return -1;

	elem = config_setting_lookup(cs, CONF_STR_NAME);

	if (elem == NULL) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return -1;
	}

	val_str = config_setting_get_string_elem(elem, 0);

	if (val_str == NULL) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" \"" CONF_STR_PREFIX "\" found\n");
		return -1;
	}

	templ->name_prefix = strdup(val_str);

	if (templ->name_prefix == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	val_i = config_setting_get_int_elem(elem, 1);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" \"" CONF_STR_IDX "\" found\n");
		return -1;
	}

	templ->name_idx = val_i;
	val_i = config_setting_get_int_elem(elem, 2);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" \"" CONF_STR_INC "\" found\n");
		return -1;
	}

	templ->name_inc = val_i;

	if (config_setting_lookup_string(cs, CONF_STR_ACTION, &val_str) == CONFIG_TRUE) {
		templ->action = strdup(val_str);

		if (templ->action == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");

		if (strcmp(templ->action, DROP) == 0)
			return num;
	}

	if (config_setting_lookup_int(cs, CONF_STR_NUM_QS, &val_i) == CONFIG_TRUE)
		templ->num_qs = val_i;

	elem = config_setting_lookup(cs, CONF_STR_QUEUE);

	if (elem == NULL) {
		ODPH_ERR("No \"" CONF_STR_QUEUE "\" found\n");
		return -1;
	}

	val_str = config_setting_get_string_elem(elem, 0);

	if (val_str == NULL) {
		ODPH_ERR("No \"" CONF_STR_QUEUE "\" \"" CONF_STR_PREFIX "\" found\n");
		return -1;
	}

	templ->queue_prefix = strdup(val_str);

	if (templ->queue_prefix == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	val_i = config_setting_get_int_elem(elem, 1);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_QUEUE "\" \"" CONF_STR_IDX "\" found\n");
		return -1;
	}

	templ->queue_idx = val_i;
	val_i = config_setting_get_int_elem(elem, 2);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_QUEUE "\" \"" CONF_STR_INC "\" found\n");
		return -1;
	}

	templ->queue_inc = val_i;

	if (config_setting_lookup_string(cs, CONF_STR_TYPE, &val_str) == CONFIG_TRUE) {
		templ->type = strdup(val_str);

		if (templ->type == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	}

	if (config_setting_lookup_int(cs, CONF_STR_HASH_IPV4_UDP, &val_i) == CONFIG_TRUE)
		templ->h_ipv4_udp = val_i;

	if (config_setting_lookup_int(cs, CONF_STR_HASH_IPV4_TCP, &val_i) == CONFIG_TRUE)
		templ->h_ipv4_tcp = val_i;

	if (config_setting_lookup_int(cs, CONF_STR_HASH_IPV4, &val_i) == CONFIG_TRUE)
		templ->h_ipv4 = val_i;

	if (config_setting_lookup_int(cs, CONF_STR_HASH_IPV6_UDP, &val_i) == CONFIG_TRUE)
		templ->h_ipv6_udp = val_i;

	if (config_setting_lookup_int(cs, CONF_STR_HASH_IPV6_TCP, &val_i) == CONFIG_TRUE)
		templ->h_ipv6_tcp = val_i;

	if (config_setting_lookup_int(cs, CONF_STR_HASH_IPV6, &val_i) == CONFIG_TRUE)
		templ->h_ipv6 = val_i;

	if (config_setting_lookup_string(cs, CONF_STR_POOL, &val_str) == CONFIG_TRUE) {
		templ->pool = strdup(val_str);

		if (templ->pool == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	}

	return num;
}

static odp_bool_t parse_cos_entry_from_template(cos_parse_template_t *templ, cos_parse_t *cos)
{
	char cos_name[ODP_COS_NAME_LEN];
	char queue_name[ODP_QUEUE_NAME_LEN];

	memset(cos, 0, sizeof(*cos));
	memset(cos_name, 0, sizeof(cos_name));
	memset(queue_name, 0, sizeof(queue_name));
	cos->cos = ODP_COS_INVALID;
	cos->def_pktio = ODP_PKTIO_INVALID;
	odp_cls_cos_param_init(&cos->cos_param);
	cos->cos_param.hash_proto.all_bits = 0U;
	odp_queue_param_init(&cos->q_param);
	(void)snprintf(cos_name, sizeof(cos_name), "%s%u", templ->name_prefix, templ->name_idx);
	templ->name_idx += templ->name_inc;
	cos->name = strdup(cos_name);

	if (cos->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (templ->action != NULL) {
		if (strcmp(templ->action, DROP) == 0) {
			cos->cos_param.action = ODP_COS_ACTION_DROP;
		} else if (strcmp(templ->action, ENQUEUE) == 0) {
			cos->cos_param.action = ODP_COS_ACTION_ENQUEUE;
		} else {
			ODPH_ERR("No valid \"" CONF_STR_ACTION "\" found\n");
			return false;
		}
	}

	if (cos->cos_param.action == ODP_COS_ACTION_DROP)
		return true;

	if (templ->num_qs > 0U)
		cos->cos_param.num_queue = templ->num_qs;

	if (cos->cos_param.num_queue == 1U) {
		(void)snprintf(queue_name, sizeof(queue_name), "%s%u", templ->queue_prefix,
			       templ->queue_idx);
		templ->queue_idx += templ->queue_inc;
		cos->queue = strdup(queue_name);

		if (cos->queue == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	} else {
		if (templ->type != NULL) {
			if (strcmp(templ->type, PLAIN) == 0) {
				cos->q_param.type = ODP_QUEUE_TYPE_PLAIN;
			} else if (strcmp(templ->type, SCHEDULED) == 0) {
				cos->q_param.type = ODP_QUEUE_TYPE_SCHED;
			} else {
				ODPH_ERR("No valid \"" CONF_STR_TYPE "\" found\n");
				return false;
			}
		}

		cos->cos_param.hash_proto.proto.ipv4_udp = templ->h_ipv4_udp;
		cos->cos_param.hash_proto.proto.ipv4_tcp = templ->h_ipv4_tcp;
		cos->cos_param.hash_proto.proto.ipv4 = templ->h_ipv4;
		cos->cos_param.hash_proto.proto.ipv6_udp = templ->h_ipv6_udp;
		cos->cos_param.hash_proto.proto.ipv6_tcp = templ->h_ipv6_tcp;
		cos->cos_param.hash_proto.proto.ipv6 = templ->h_ipv6;
	}

	if (templ->pool != NULL) {
		cos->pool = strdup(templ->pool);

		if (cos->pool == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	}

	return true;
}

static void free_cos_entry(cos_parse_t *cos)
{
	free(cos->name);
	free(cos->queue);
	free(cos->pool);
	free(cos->def);

	if (cos->def_pktio != ODP_PKTIO_INVALID)
		(void)odp_pktio_default_cos_set(cos->def_pktio, ODP_COS_INVALID);

	if (cos->cos != ODP_COS_INVALID)
		(void)odp_cos_destroy(cos->cos);
}

static void free_cos_template(cos_parse_template_t *templ)
{
	free(templ->name_prefix);
	free(templ->action);
	free(templ->queue_prefix);
	free(templ->type);
	free(templ->pool);
}

static res_t parse_pmr_entry(config_setting_t *cs, pmr_parse_t *pmr)
{
	const char *val_str;
	int val_i, num;
	config_setting_t *elem;

	if (config_setting_lookup(cs, CONF_STR_PARSE_TEMPLATE) != NULL)
		return PARSE_TEMPL;

	memset(pmr, 0, sizeof(*pmr));
	pmr->pmr = ODP_PMR_INVALID;
	odp_cls_pmr_param_init(&pmr->param);

	if (config_setting_lookup_string(cs, CONF_STR_NAME, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return PARSE_NOK;
	}

	pmr->name = strdup(val_str);

	if (pmr->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (config_setting_lookup_string(cs, CONF_STR_SRC_COS, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_SRC_COS "\" found\n");
		return PARSE_NOK;
	}

	pmr->src = strdup(val_str);

	if (pmr->src == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (config_setting_lookup_string(cs, CONF_STR_DST_COS, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_DST_COS "\" found\n");
		return PARSE_NOK;
	}

	pmr->dst = strdup(val_str);

	if (pmr->dst == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (config_setting_lookup_string(cs, CONF_STR_TERM, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_TERM "\" found\n");
		return PARSE_NOK;
	}

	if (strcmp(val_str, LEN) == 0) {
		pmr->param.term = ODP_PMR_LEN;
	} else if (strcmp(val_str, ETH_0) == 0) {
		pmr->param.term = ODP_PMR_ETHTYPE_0;
	} else if (strcmp(val_str, ETH_X) == 0) {
		pmr->param.term = ODP_PMR_ETHTYPE_X;
	} else if (strcmp(val_str, VLAN_0) == 0) {
		pmr->param.term = ODP_PMR_VLAN_ID_0;
	} else if (strcmp(val_str, VLAN_X) == 0) {
		pmr->param.term = ODP_PMR_VLAN_ID_X;
	} else if (strcmp(val_str, VLAN_PCP) == 0) {
		pmr->param.term = ODP_PMR_VLAN_PCP_0;
	} else if (strcmp(val_str, DMAC) == 0) {
		pmr->param.term = ODP_PMR_DMAC;
	} else if (strcmp(val_str, IPPROTO) == 0) {
		pmr->param.term = ODP_PMR_IPPROTO;
	} else if (strcmp(val_str, IP_DSCP) == 0) {
		pmr->param.term = ODP_PMR_IP_DSCP;
	} else if (strcmp(val_str, UDP_DPORT) == 0) {
		pmr->param.term = ODP_PMR_UDP_DPORT;
	} else if (strcmp(val_str, TCP_DPORT) == 0) {
		pmr->param.term = ODP_PMR_TCP_DPORT;
	} else if (strcmp(val_str, UDP_SPORT) == 0) {
		pmr->param.term = ODP_PMR_UDP_SPORT;
	} else if (strcmp(val_str, TCP_SPORT) == 0) {
		pmr->param.term = ODP_PMR_TCP_SPORT;
	} else if (strcmp(val_str, SIP_ADDR) == 0) {
		pmr->param.term = ODP_PMR_SIP_ADDR;
	} else if (strcmp(val_str, DIP_ADDR) == 0) {
		pmr->param.term = ODP_PMR_DIP_ADDR;
	} else if (strcmp(val_str, SIP6_ADDR) == 0) {
		pmr->param.term = ODP_PMR_SIP6_ADDR;
	} else if (strcmp(val_str, DIP6_ADDR) == 0) {
		pmr->param.term = ODP_PMR_DIP6_ADDR;
	} else if (strcmp(val_str, IPSEC_SPI) == 0) {
		pmr->param.term = ODP_PMR_IPSEC_SPI;
	} else if (strcmp(val_str, LD_VNI) == 0) {
		pmr->param.term = ODP_PMR_LD_VNI;
	} else if (strcmp(val_str, CUSTOM_FRAME) == 0) {
		pmr->param.term = ODP_PMR_CUSTOM_FRAME;
	} else if (strcmp(val_str, CUSTOM_L3) == 0) {
		pmr->param.term = ODP_PMR_CUSTOM_L3;
	} else if (strcmp(val_str, SCTP_SPORT) == 0) {
		pmr->param.term = ODP_PMR_SCTP_SPORT;
	} else if (strcmp(val_str, SCTP_DPORT) == 0) {
		pmr->param.term = ODP_PMR_SCTP_DPORT;
	} else {
		ODPH_ERR("No valid \"" CONF_STR_TERM "\" found\n");
		return PARSE_NOK;
	}

	elem = config_setting_lookup(cs, CONF_STR_MATCH_VALUE);

	if (elem == NULL) {
		ODPH_ERR("No \"" CONF_STR_MATCH_VALUE "\" entries found\n");
		return PARSE_NOK;
	}

	num = config_setting_length(elem);

	if (num == 0) {
		ODPH_ERR("No valid \"" CONF_STR_MATCH_VALUE "\" entries found\n");
		return PARSE_NOK;
	}

	pmr->val_arr = calloc(1U, num * sizeof(*pmr->val_arr));

	if (pmr->val_arr == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i)
		pmr->val_arr[i] = (uint8_t)config_setting_get_int_elem(elem, i);

	pmr->param.match.value = pmr->val_arr;
	elem = config_setting_lookup(cs, CONF_STR_MATCH_MASK);

	if (elem == NULL) {
		ODPH_ERR("No \"" CONF_STR_MATCH_MASK "\" entries found\n");
		return PARSE_NOK;
	}

	num = config_setting_length(elem);

	if (num == 0) {
		ODPH_ERR("No valid \"" CONF_STR_MATCH_MASK "\" entries found\n");
		return PARSE_NOK;
	}

	pmr->mask_arr = calloc(1U, num * sizeof(*pmr->mask_arr));

	if (pmr->mask_arr == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i)
		pmr->mask_arr[i] = (uint8_t)config_setting_get_int_elem(elem, i);

	pmr->param.match.mask = pmr->mask_arr;

	if (config_setting_lookup_int(cs, CONF_STR_VAL_SZ, &val_i) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_VAL_SZ "\" found\n");
		return PARSE_NOK;
	}

	pmr->param.val_sz = val_i;

	if (pmr->param.term == ODP_PMR_CUSTOM_FRAME || pmr->param.term == ODP_PMR_CUSTOM_L3) {
		if (config_setting_lookup_int(cs, CONF_STR_OFFSET, &val_i) == CONFIG_FALSE) {
			ODPH_ERR("No \"" CONF_STR_OFFSET "\" found\n");
			return PARSE_NOK;
		}

		pmr->param.offset = val_i;
	}

	return PARSE_OK;
}

static int parse_pmr_entry_template(config_setting_t *cs, pmr_parse_template_t *templ)
{
	int val_i;
	uint32_t num;
	config_setting_t *elem1, *elem2;
	const char *val_str;

	memset(templ, 0, sizeof(*templ));

	if (config_setting_lookup_int(cs, CONF_STR_PARSE_TEMPLATE, &val_i) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_PARSE_TEMPLATE "\" found\n");
		return -1;
	}

	num = val_i;

	if (num == 0U)
		return -1;

	elem1 = config_setting_lookup(cs, CONF_STR_NAME);

	if (elem1 == NULL) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return -1;
	}

	val_str = config_setting_get_string_elem(elem1, 0);

	if (val_str == NULL) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" \"" CONF_STR_PREFIX "\" found\n");
		return -1;
	}

	templ->name_prefix = strdup(val_str);

	if (templ->name_prefix == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	val_i = config_setting_get_int_elem(elem1, 1);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" \"" CONF_STR_IDX "\" found\n");
		return -1;
	}

	templ->name_idx = val_i;
	val_i = config_setting_get_int_elem(elem1, 2);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" \"" CONF_STR_INC "\" found\n");
		return -1;
	}

	templ->name_inc = val_i;
	elem1 = config_setting_lookup(cs, CONF_STR_SRC_COS);

	if (elem1 == NULL) {
		ODPH_ERR("No \"" CONF_STR_SRC_COS "\" found\n");
		return -1;
	}

	val_str = config_setting_get_string_elem(elem1, 0);

	if (val_str == NULL) {
		ODPH_ERR("No \"" CONF_STR_SRC_COS "\" \"" CONF_STR_PREFIX "\" found\n");
		return -1;
	}

	templ->src_prefix = strdup(val_str);

	if (templ->src_prefix == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	val_i = config_setting_get_int_elem(elem1, 1);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_SRC_COS "\" \"" CONF_STR_IDX "\" found\n");
		return -1;
	}

	templ->src_idx = val_i;
	val_i = config_setting_get_int_elem(elem1, 2);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_SRC_COS "\" \"" CONF_STR_INC "\" found\n");
		return -1;
	}

	templ->src_inc = val_i;
	elem1 = config_setting_lookup(cs, CONF_STR_DST_COS);

	if (elem1 == NULL) {
		ODPH_ERR("No \"" CONF_STR_DST_COS "\" found\n");
		return -1;
	}

	val_str = config_setting_get_string_elem(elem1, 0);

	if (val_str == NULL) {
		ODPH_ERR("No \"" CONF_STR_DST_COS "\" \"" CONF_STR_PREFIX "\" found\n");
		return -1;
	}

	templ->dst_prefix = strdup(val_str);

	if (templ->dst_prefix == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	val_i = config_setting_get_int_elem(elem1, 1);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_DST_COS "\" \"" CONF_STR_IDX "\" found\n");
		return -1;
	}

	templ->dst_idx = val_i;
	val_i = config_setting_get_int_elem(elem1, 2);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_DST_COS "\" \"" CONF_STR_INC "\" found\n");
		return -1;
	}

	templ->dst_inc = val_i;

	if (config_setting_lookup_string(cs, CONF_STR_TERM, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_TERM "\" found\n");
		return -1;
	}

	templ->term = strdup(val_str);

	if (templ->term == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	elem1 = config_setting_lookup(cs, CONF_STR_MATCH_VALUE);

	if (elem1 == NULL) {
		ODPH_ERR("No \"" CONF_STR_MATCH_VALUE "\" found\n");
		return -1;
	}

	elem2 = config_setting_get_elem(elem1, 0);

	if (elem2 == NULL) {
		ODPH_ERR("No \"" CONF_STR_MATCH_VALUE "\" found\n");
		return -1;
	}

	val_i = config_setting_length(elem2);

	if (val_i == 0) {
		ODPH_ERR("No valid \"" CONF_STR_MATCH_VALUE "\" entries found\n");
		return -1;
	}

	templ->val_arr = calloc(1U, val_i * sizeof(*templ->val_arr));

	if (templ->val_arr == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < val_i; ++i)
		templ->val_arr[i] = (uint8_t)config_setting_get_int_elem(elem2, i);

	val_i = config_setting_get_int_elem(elem1, 1);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_MATCH_VALUE "\" \"" CONF_STR_INC "\" found\n");
		return -1;
	}

	templ->val_arr_inc = val_i;
	elem1 = config_setting_lookup(cs, CONF_STR_MATCH_MASK);

	if (elem1 == NULL) {
		ODPH_ERR("No \"" CONF_STR_MATCH_MASK "\" found\n");
		return -1;
	}

	val_i = config_setting_length(elem1);

	if (val_i == 0) {
		ODPH_ERR("No valid \"" CONF_STR_MATCH_MASK "\" entries found\n");
		return -1;
	}

	templ->mask_arr = calloc(1U, val_i * sizeof(*templ->mask_arr));

	if (templ->mask_arr == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < val_i; ++i)
		templ->mask_arr[i] = (uint8_t)config_setting_get_int_elem(elem1, i);

	if (config_setting_lookup_int(cs, CONF_STR_VAL_SZ, &val_i) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_VAL_SZ "\" found\n");
		return PARSE_NOK;
	}

	templ->val_sz = val_i;

	if (strcmp(templ->term, CUSTOM_FRAME) == 0 || strcmp(templ->term, CUSTOM_L3) == 0) {
		if (config_setting_lookup_int(cs, CONF_STR_OFFSET, &val_i) == CONFIG_FALSE) {
			ODPH_ERR("No \"" CONF_STR_OFFSET "\" found\n");
			return PARSE_NOK;
		}

		templ->offset = val_i;
	}

	return num;
}

static void increment_value_array(uint8_t data[], uint32_t inc, uint32_t len)
{
	int i = len - 1, j = 0;
	uint32_t carry = inc, digit, sum;
	uint8_t tmp[len + sizeof(inc) + 1U];

	while (i >= 0 || carry != 0) {
		digit = i >= 0 ? data[i] : 0;
		sum = digit + (carry & 0xFFU);
		tmp[j++] = (uint8_t)(sum & 0xFFU);
		carry = (carry >> 8U) + (sum >> 8U);
		i--;
	}

	for (uint32_t k = 0U; k < len; k++)
		data[len - 1U - k] = tmp[k];
}

static odp_bool_t parse_pmr_entry_from_template(pmr_parse_template_t *templ, pmr_parse_t *pmr)
{
	char name[ODP_COS_NAME_LEN];

	memset(pmr, 0, sizeof(*pmr));
	memset(name, 0, sizeof(name));
	pmr->pmr = ODP_PMR_INVALID;
	odp_cls_pmr_param_init(&pmr->param);
	(void)snprintf(name, sizeof(name), "%s%u", templ->name_prefix, templ->name_idx);
	templ->name_idx += templ->name_inc;
	pmr->name = strdup(name);

	if (pmr->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	memset(name, 0, sizeof(name));
	(void)snprintf(name, sizeof(name), "%s%u", templ->src_prefix, templ->src_idx);
	templ->src_idx += templ->src_inc;
	pmr->src = strdup(name);

	if (pmr->src == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	memset(name, 0, sizeof(name));
	(void)snprintf(name, sizeof(name), "%s%u", templ->dst_prefix, templ->dst_idx);
	templ->dst_idx += templ->dst_inc;
	pmr->dst = strdup(name);

	if (pmr->dst == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (strcmp(templ->term, LEN) == 0) {
		pmr->param.term = ODP_PMR_LEN;
	} else if (strcmp(templ->term, ETH_0) == 0) {
		pmr->param.term = ODP_PMR_ETHTYPE_0;
	} else if (strcmp(templ->term, ETH_X) == 0) {
		pmr->param.term = ODP_PMR_ETHTYPE_X;
	} else if (strcmp(templ->term, VLAN_0) == 0) {
		pmr->param.term = ODP_PMR_VLAN_ID_0;
	} else if (strcmp(templ->term, VLAN_X) == 0) {
		pmr->param.term = ODP_PMR_VLAN_ID_X;
	} else if (strcmp(templ->term, VLAN_PCP) == 0) {
		pmr->param.term = ODP_PMR_VLAN_PCP_0;
	} else if (strcmp(templ->term, DMAC) == 0) {
		pmr->param.term = ODP_PMR_DMAC;
	} else if (strcmp(templ->term, IPPROTO) == 0) {
		pmr->param.term = ODP_PMR_IPPROTO;
	} else if (strcmp(templ->term, IP_DSCP) == 0) {
		pmr->param.term = ODP_PMR_IP_DSCP;
	} else if (strcmp(templ->term, UDP_DPORT) == 0) {
		pmr->param.term = ODP_PMR_UDP_DPORT;
	} else if (strcmp(templ->term, TCP_DPORT) == 0) {
		pmr->param.term = ODP_PMR_TCP_DPORT;
	} else if (strcmp(templ->term, UDP_SPORT) == 0) {
		pmr->param.term = ODP_PMR_UDP_SPORT;
	} else if (strcmp(templ->term, TCP_SPORT) == 0) {
		pmr->param.term = ODP_PMR_TCP_SPORT;
	} else if (strcmp(templ->term, SIP_ADDR) == 0) {
		pmr->param.term = ODP_PMR_SIP_ADDR;
	} else if (strcmp(templ->term, DIP_ADDR) == 0) {
		pmr->param.term = ODP_PMR_DIP_ADDR;
	} else if (strcmp(templ->term, SIP6_ADDR) == 0) {
		pmr->param.term = ODP_PMR_SIP6_ADDR;
	} else if (strcmp(templ->term, DIP6_ADDR) == 0) {
		pmr->param.term = ODP_PMR_DIP6_ADDR;
	} else if (strcmp(templ->term, IPSEC_SPI) == 0) {
		pmr->param.term = ODP_PMR_IPSEC_SPI;
	} else if (strcmp(templ->term, LD_VNI) == 0) {
		pmr->param.term = ODP_PMR_LD_VNI;
	} else if (strcmp(templ->term, CUSTOM_FRAME) == 0) {
		pmr->param.term = ODP_PMR_CUSTOM_FRAME;
	} else if (strcmp(templ->term, CUSTOM_L3) == 0) {
		pmr->param.term = ODP_PMR_CUSTOM_L3;
	} else if (strcmp(templ->term, SCTP_SPORT) == 0) {
		pmr->param.term = ODP_PMR_SCTP_SPORT;
	} else if (strcmp(templ->term, SCTP_DPORT) == 0) {
		pmr->param.term = ODP_PMR_SCTP_DPORT;
	} else {
		ODPH_ERR("No valid \"" CONF_STR_TERM "\" found\n");
		return false;
	}

	pmr->val_arr = malloc(templ->val_sz);

	if (pmr->val_arr == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	memcpy(pmr->val_arr, templ->val_arr, templ->val_sz);
	pmr->mask_arr = malloc(templ->val_sz);

	if (pmr->mask_arr == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	memcpy(pmr->mask_arr, templ->mask_arr, templ->val_sz);
	pmr->param.match.value = pmr->val_arr;
	pmr->param.match.mask = pmr->mask_arr;
	pmr->param.val_sz = templ->val_sz;
	pmr->param.offset = templ->offset;
	increment_value_array(templ->val_arr, templ->val_arr_inc, templ->val_sz);

	return true;
}

static void free_pmr_entry(pmr_parse_t *pmr)
{
	free(pmr->name);
	free(pmr->src);
	free(pmr->dst);
	free(pmr->val_arr);
	free(pmr->mask_arr);

	if (pmr->pmr != ODP_PMR_INVALID)
		(void)odp_cls_pmr_destroy(pmr->pmr);
}

static void free_pmr_template(pmr_parse_template_t *templ)
{
	free(templ->name_prefix);
	free(templ->src_prefix);
	free(templ->dst_prefix);
	free(templ->term);
	free(templ->val_arr);
	free(templ->mask_arr);
}

static odp_bool_t classifier_parser_init(config_t *config)
{
	config_setting_t *cs, *elem1, *elem2, *tmp;
	int num1, num2, ret;
	cos_parse_t *cos;
	res_t res;
	cos_parse_template_t cos_templ;
	pmr_parse_t *pmr;
	pmr_parse_template_t pmr_templ;

	cs = config_lookup(config, CLASSIFICATION_DOMAIN);

	if (cs == NULL)	{
		printf("Nothing to parse for \"" CLASSIFICATION_DOMAIN "\" domain\n");
		return true;
	}

	elem1 = config_setting_lookup(cs, CONF_STR_COS);

	if (elem1 == NULL) {
		ODPH_ERR("No \"" CONF_STR_COS "\" entries found\n");
		return false;
	}

	num1 = config_setting_length(elem1);

	if (num1 == 0) {
		ODPH_ERR("No valid \"" CONF_STR_COS "\" entries found\n");
		return false;
	}

	elem2 = config_setting_lookup(cs, CONF_STR_PMR);

	if (elem2 == NULL) {
		ODPH_ERR("No \"" CONF_STR_PMR "\" entries found\n");
		return false;
	}

	num2 = config_setting_length(elem2);

	if (num2 == 0) {
		ODPH_ERR("No valid \"" CONF_STR_PMR "\" entries found\n");
		return false;
	}

	cls.coss = calloc(1U, num1 * sizeof(*cls.coss));

	if (cls.coss == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num1; ++i) {
		tmp = config_setting_get_elem(elem1, i);

		if (tmp == NULL) {
			ODPH_ERR("Unparsable \"" CONF_STR_COS "\" entry (%d)\n", i);
			return false;
		}

		cos = &cls.coss[cls.num_cos];
		res = parse_cos_entry(tmp, cos);

		if (res == PARSE_NOK) {
			ODPH_ERR("Invalid \"" CONF_STR_COS "\" entry (%d)\n", i);
			free_cos_entry(cos);
			return false;
		} else if (res == PARSE_TEMPL) {
			ret = parse_cos_entry_template(tmp, &cos_templ);

			if (ret == -1) {
				ODPH_ERR("Invalid \"" CONF_STR_COS "\" entry (%d)\n", i);
				return false;
			}

			cls.coss = realloc(cls.coss, (ret + cls.num_cos  + (num1 - i - 1)) *
					   sizeof(*cls.coss));

			if (cls.coss == NULL)
				ODPH_ABORT("Error allocating memory, aborting\n");

			for (int j = 0; j < ret; ++j) {
				cos = &cls.coss[cls.num_cos];

				if (!parse_cos_entry_from_template(&cos_templ, cos)) {
					ODPH_ERR("Invalid \"" CONF_STR_COS "\" entry (%d)\n", i);
					free_cos_template(&cos_templ);
					free_cos_entry(cos);
					return false;
				}

				++cls.num_cos;
			}

			free_cos_template(&cos_templ);
		} else {
			++cls.num_cos;
		}
	}

	cls.pmrs = calloc(1U, num2 * sizeof(*cls.pmrs));

	if (cls.pmrs == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num2; ++i) {
		tmp = config_setting_get_elem(elem2, i);

		if (tmp == NULL) {
			ODPH_ERR("Unparsable \"" CONF_STR_PMR "\" entry (%d)\n", i);
			return false;
		}

		pmr = &cls.pmrs[cls.num_pmr];
		res = parse_pmr_entry(tmp, pmr);

		if (res == PARSE_NOK) {
			ODPH_ERR("Invalid \"" CONF_STR_PMR "\" entry (%d)\n", i);
			free_pmr_entry(pmr);
			return false;
		} else if (res == PARSE_TEMPL) {
			ret = parse_pmr_entry_template(tmp, &pmr_templ);

			if (ret == -1) {
				ODPH_ERR("Invalid \"" CONF_STR_PMR "\" entry (%d)\n", i);
				return false;
			}

			cls.pmrs = realloc(cls.pmrs, (ret + cls.num_pmr + (num2 - i - 1)) *
					   sizeof(*cls.pmrs));

			if (cls.pmrs == NULL)
				ODPH_ABORT("Error allocating memory, aborting\n");

			for (int j = 0; j < ret; ++j) {
				pmr = &cls.pmrs[cls.num_pmr];

				if (!parse_pmr_entry_from_template(&pmr_templ, pmr)) {
					ODPH_ERR("Invalid \"" CONF_STR_PMR "\" entry (%d)\n", i);
					free_pmr_template(&pmr_templ);
					free_pmr_entry(pmr);
					return false;
				}

				++cls.num_pmr;
			}

			free_pmr_template(&pmr_templ);
		} else {
			++cls.num_pmr;
		}
	}

	return true;
}

static odp_bool_t classifier_parser_deploy(void)
{
	cos_parse_t *cos;
	odp_pktio_t pktio;
	pmr_parse_t *pmr;
	odp_cos_t src, dst;

	printf("\n*** " CLASSIFICATION_DOMAIN " resources ***\n");

	for (uint32_t i = 0U; i < cls.num_cos; ++i) {
		cos = &cls.coss[i];

		if (cos->queue != NULL)
			cos->cos_param.queue = (odp_queue_t)config_parser_get(QUEUE_DOMAIN,
									      cos->queue);

		if (cos->pool != NULL)
			cos->cos_param.pool = (odp_pool_t)config_parser_get(POOL_DOMAIN,
									    cos->pool);

		cos->cos = odp_cls_cos_create(cos->name, &cos->cos_param);

		if (cos->cos == ODP_COS_INVALID) {
			ODPH_ERR("Error creating CoS (%s)\n", cos->name);
			return false;
		}

		if (cos->def != NULL) {
			pktio = (odp_pktio_t)config_parser_get(PKTIO_DOMAIN, cos->def);

			if (odp_pktio_default_cos_set(pktio, cos->cos) < 0) {
				ODPH_ERR("Error setting default CoS (%s)\n", cos->name);
				return false;
			}

			cos->def_pktio = pktio;
		}

		printf("\nname: %s\n", cos->name);
	}

	for (uint32_t i = 0U; i < cls.num_pmr; ++i) {
		pmr = &cls.pmrs[i];
		src = (odp_cos_t)config_parser_get(CLASSIFICATION_DOMAIN, pmr->src);
		dst = (odp_cos_t)config_parser_get(CLASSIFICATION_DOMAIN, pmr->dst);
		pmr->pmr = odp_cls_pmr_create(&pmr->param, 1, src, dst);

		if (pmr->pmr == ODP_PMR_INVALID) {
			ODPH_ERR("Error creating PMR (%s)\n", pmr->name);
			return false;
		}

		printf("\nname: %s\n", pmr->name);
	}

	odp_cls_print_all();

	return true;
}

static void classifier_parser_destroy(void)
{
	for (uint32_t i = 0U; i < cls.num_pmr; ++i)
		free_pmr_entry(&cls.pmrs[i]);

	for (uint32_t i = 0U; i < cls.num_cos; ++i)
		free_cos_entry(&cls.coss[i]);

	free(cls.pmrs);
	free(cls.coss);
}

static uintptr_t classifier_parser_get_resource(const char *resource)
{
	cos_parse_t *parse;
	odp_cos_t cos = ODP_COS_INVALID;

	for (uint32_t i = 0U; i < cls.num_cos; ++i) {
		parse = &cls.coss[i];

		if (strcmp(parse->name, resource) != 0)
			continue;

		cos = parse->cos;
		break;
	}

	if (cos == ODP_COS_INVALID)
		ODPH_ABORT("No resource found (%s), aborting\n", resource);

	return (uintptr_t)cos;
}

CONFIG_PARSER_AUTOREGISTER(LOW_PRIO, CLASSIFICATION_DOMAIN, classifier_parser_init,
			   classifier_parser_deploy, NULL, classifier_parser_destroy,
			   classifier_parser_get_resource)
