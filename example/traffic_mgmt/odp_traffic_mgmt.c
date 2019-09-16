/* Copyright 2015 EZchip Semiconductor Ltd. All Rights Reserved.
 *
 * Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#define _GNU_SOURCE

#include <execinfo.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <odp_api.h>

#define NUM_SVC_CLASSES     4
#define USERS_PER_SVC_CLASS 2
#define APPS_PER_USER       2
#define TM_QUEUES_PER_APP   2
#define NUM_USERS           (USERS_PER_SVC_CLASS * NUM_SVC_CLASSES)
#define NUM_TM_QUEUES       (NUM_USERS * APPS_PER_USER * TM_QUEUES_PER_APP)
#define TM_QUEUES_PER_USER  (TM_QUEUES_PER_APP * APPS_PER_USER)
#define TM_QUEUES_PER_CLASS (USERS_PER_SVC_CLASS * TM_QUEUES_PER_USER)
#define MAX_NODES_PER_LEVEL (NUM_USERS * APPS_PER_USER)

#define KBPS   1000
#define MBPS   1000000
#define PERCENT(percent)  (100 * percent)

#define FALSE  0
#define TRUE   1

#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define RANDOM_BUF_LEN  1024

typedef struct {
	odp_tm_shaper_params_t    shaper_params;
	odp_tm_threshold_params_t threshold_params;
	odp_tm_wred_params_t      wred_params[ODP_NUM_PACKET_COLORS];
} profile_params_set_t;

typedef struct {
	odp_tm_shaper_t    shaper_profile;
	odp_tm_threshold_t threshold_profile;
	odp_tm_wred_t      wred_profiles[ODP_NUM_PACKET_COLORS];
} profile_set_t;

static const odp_init_t ODP_INIT_PARAMS = {
	.log_fn   = odp_override_log,
	.abort_fn = odp_override_abort
};

static profile_params_set_t COMPANY_PROFILE_PARAMS = {
	.shaper_params = {
		.commit_bps = 50  * MBPS,  .commit_burst      = 1000000,
		.peak_bps   = 0,           .peak_burst        = 0,
		.dual_rate  = FALSE,       .shaper_len_adjust = 20
	},

	.threshold_params = {
		.max_pkts  = 100000,    .enable_max_pkts  = TRUE,
		.max_bytes = 10000000,  .enable_max_bytes = TRUE
	},

	.wred_params = {
		[ODP_PACKET_GREEN ... ODP_PACKET_YELLOW] = {
			.min_threshold     = PERCENT(70),
			.med_threshold     = PERCENT(90),
			.med_drop_prob     = PERCENT(80),
			.max_drop_prob     = PERCENT(100),
			.enable_wred       = TRUE,
			.use_byte_fullness = FALSE,
		},

		[ODP_PACKET_RED] = {
			.min_threshold     = PERCENT(40),
			.med_threshold     = PERCENT(70),
			.med_drop_prob     = PERCENT(70),
			.max_drop_prob     = PERCENT(100),
			.enable_wred       = TRUE,
			.use_byte_fullness = FALSE,
		},
	}
};

static profile_params_set_t COS0_PROFILE_PARAMS = {
	.shaper_params = {
		.commit_bps = 1 * MBPS,  .commit_burst      = 100000,
		.peak_bps   = 4 * MBPS,  .peak_burst        = 200000,
		.dual_rate  = FALSE,     .shaper_len_adjust = 20
	},

	.threshold_params = {
		.max_pkts  = 10000,    .enable_max_pkts  = TRUE,
		.max_bytes = 1000000,  .enable_max_bytes = TRUE
	},

	.wred_params = {
		[ODP_PACKET_GREEN ... ODP_PACKET_YELLOW] = {
			.min_threshold     = PERCENT(80),
			.med_threshold     = PERCENT(90),
			.med_drop_prob     = PERCENT(50),
			.max_drop_prob     = PERCENT(100),
			.enable_wred       = TRUE,
			.use_byte_fullness = FALSE,
		},

		[ODP_PACKET_RED] = {
			.min_threshold     = PERCENT(60),
			.med_threshold     = PERCENT(80),
			.med_drop_prob     = PERCENT(70),
			.max_drop_prob     = PERCENT(100),
			.enable_wred       = TRUE,
			.use_byte_fullness = FALSE,
		},
	}
};

static profile_params_set_t COS1_PROFILE_PARAMS = {
	.shaper_params = {
		.commit_bps = 500  * KBPS,  .commit_burst      = 50000,
		.peak_bps   = 1500 * KBPS,  .peak_burst        = 150000,
		.dual_rate  = FALSE,        .shaper_len_adjust = 20
	},

	.threshold_params = {
		.max_pkts  = 5000,    .enable_max_pkts  = TRUE,
		.max_bytes = 500000,  .enable_max_bytes = TRUE
	},

	.wred_params = {
		[ODP_PACKET_GREEN ... ODP_PACKET_YELLOW] = {
			.min_threshold     = PERCENT(40),
			.med_threshold     = PERCENT(90),
			.med_drop_prob     = PERCENT(70),
			.max_drop_prob     = PERCENT(100),
			.enable_wred       = TRUE,
			.use_byte_fullness = FALSE,
		},

		[ODP_PACKET_RED] = {
			.min_threshold     = PERCENT(50),
			.med_threshold     = PERCENT(80),
			.med_drop_prob     = PERCENT(80),
			.max_drop_prob     = PERCENT(100),
			.enable_wred       = TRUE,
			.use_byte_fullness = FALSE,
		},
	}
};

static profile_params_set_t COS2_PROFILE_PARAMS = {
	.shaper_params = {
		.commit_bps = 200 * KBPS,  .commit_burst      = 20000,
		.peak_bps   = 400 * KBPS,  .peak_burst        = 40000,
		.dual_rate  = FALSE,       .shaper_len_adjust = 20
	},

	.threshold_params = {
		.max_pkts  = 1000,    .enable_max_pkts  = TRUE,
		.max_bytes = 100000,  .enable_max_bytes = TRUE
	},

	.wred_params = {
		[ODP_PACKET_GREEN ... ODP_PACKET_YELLOW] = {
			.min_threshold     = PERCENT(50),
			.med_threshold     = PERCENT(80),
			.med_drop_prob     = PERCENT(70),
			.max_drop_prob     = PERCENT(100),
			.enable_wred       = TRUE,
			.use_byte_fullness = FALSE,
		},

		[ODP_PACKET_RED] = {
			.min_threshold     = PERCENT(40),
			.med_threshold     = PERCENT(70),
			.med_drop_prob     = PERCENT(80),
			.max_drop_prob     = PERCENT(100),
			.enable_wred       = TRUE,
			.use_byte_fullness = FALSE,
		},
	}
};

static profile_params_set_t COS3_PROFILE_PARAMS = {
	.shaper_params = {
		.commit_bps = 100 * KBPS,  .commit_burst      = 5000,
		.peak_bps   = 0,           .peak_burst        = 0,
		.dual_rate  = FALSE,       .shaper_len_adjust = 20
	},

	.threshold_params = {
		.max_pkts  = 400,    .enable_max_pkts  = TRUE,
		.max_bytes = 60000,  .enable_max_bytes = TRUE
	},

	.wred_params = {
		[ODP_PACKET_GREEN ... ODP_PACKET_YELLOW] = {
			.min_threshold     = PERCENT(40),
			.med_threshold     = PERCENT(70),
			.med_drop_prob     = PERCENT(80),
			.max_drop_prob     = PERCENT(100),
			.enable_wred       = TRUE,
			.use_byte_fullness = FALSE,
		},

		[ODP_PACKET_RED] = {
			.min_threshold     = PERCENT(30),
			.med_threshold     = PERCENT(60),
			.med_drop_prob     = PERCENT(80),
			.max_drop_prob     = PERCENT(100),
			.enable_wred       = TRUE,
			.use_byte_fullness = FALSE,
		},
	}
};

static profile_set_t COMPANY_PROFILE_SET;
static profile_set_t COS_PROFILE_SETS[NUM_SVC_CLASSES];
static profile_set_t USER_PROFILE_SETS[NUM_SVC_CLASSES];
static profile_set_t APP_PROFILE_SETS[NUM_SVC_CLASSES][APPS_PER_USER];

static odp_tm_t odp_tm_test;

static odp_pool_t odp_pool;

static odp_tm_queue_t queue_num_tbls[NUM_SVC_CLASSES][TM_QUEUES_PER_CLASS];
static uint32_t       next_queue_nums[NUM_SVC_CLASSES];

static uint8_t  random_buf[RANDOM_BUF_LEN];
static uint32_t next_rand_byte;

static odp_atomic_u32_t atomic_pkts_into_tm;
static odp_atomic_u32_t atomic_pkts_from_tm;

static uint32_t g_num_pkts_to_send = 1000;
static uint8_t  g_print_tm_stats   = TRUE;

static void tester_egress_fcn(odp_packet_t odp_pkt);

/* Returns the number of errors encountered. */

static uint32_t create_profile_set(profile_params_set_t *profile_params_set,
				   profile_set_t        *profile_set,
				   const char           *base_name,
				   uint32_t              name_idx,
				   uint32_t              shaper_scale,
				   uint32_t              threshold_scale)
{
	odp_tm_threshold_params_t threshold_params, *thresholds;
	odp_tm_shaper_params_t    shaper_params, *shaper;
	odp_tm_wred_params_t      wred_params, *wred;
	uint32_t                  err_cnt, color;
	char                      name[64], wred_name[64];

	err_cnt = 0;
	if (name_idx == 0)
		snprintf(name, sizeof(name), "%s", base_name);
	else
		snprintf(name, sizeof(name), "%s-%" PRIu32,
			 base_name, name_idx);

	odp_tm_shaper_params_init(&shaper_params);
	shaper                          = &profile_params_set->shaper_params;
	shaper_params.commit_bps        = shaper->commit_bps   * shaper_scale;
	shaper_params.peak_bps          = shaper->peak_bps     * shaper_scale;
	shaper_params.commit_burst      = shaper->commit_burst * shaper_scale;
	shaper_params.peak_burst        = shaper->peak_burst   * shaper_scale;
	shaper_params.dual_rate         = shaper->dual_rate;
	shaper_params.shaper_len_adjust = shaper->shaper_len_adjust;
	profile_set->shaper_profile     = odp_tm_shaper_create(name,
							       &shaper_params);
	if (profile_set->shaper_profile == ODP_TM_INVALID)
		err_cnt++;

	odp_tm_threshold_params_init(&threshold_params);
	thresholds = &profile_params_set->threshold_params;
	threshold_params.max_pkts = thresholds->max_pkts  * threshold_scale;
	threshold_params.max_bytes = thresholds->max_bytes * threshold_scale;
	threshold_params.enable_max_pkts  = thresholds->enable_max_pkts;
	threshold_params.enable_max_bytes = thresholds->enable_max_bytes;
	profile_set->threshold_profile =
		odp_tm_threshold_create(name, &threshold_params);

	if (profile_set->threshold_profile == ODP_TM_INVALID)
		err_cnt++;

	for (color = 0; color < ODP_NUM_PACKET_COLORS; color++) {
		snprintf(wred_name, sizeof(wred_name), "%s-%" PRIu32,
			 name, color);

		odp_tm_wred_params_init(&wred_params);
		wred = &profile_params_set->wred_params[color];
		wred_params.min_threshold     = wred->min_threshold;
		wred_params.med_threshold     = wred->med_threshold;
		wred_params.med_drop_prob     = wred->med_drop_prob;
		wred_params.max_drop_prob     = wred->max_drop_prob;
		wred_params.enable_wred       = wred->enable_wred;
		wred_params.use_byte_fullness = wred->use_byte_fullness;
		profile_set->wred_profiles[color] =
			odp_tm_wred_create(wred_name, &wred_params);
		if (profile_set->wred_profiles[color] == ODP_TM_INVALID)
			err_cnt++;
	}

	return err_cnt;
}

/* Returns the number of errors encountered. */

static uint32_t init_profile_sets(void)
{
	uint32_t class_shaper_scale, class_threshold_scale, user_shaper_scale;
	uint32_t user_threshold_scale, err_cnt, app_idx;

	class_shaper_scale    = TM_QUEUES_PER_CLASS / 2;
	class_threshold_scale = TM_QUEUES_PER_CLASS;
	user_shaper_scale     = TM_QUEUES_PER_USER / 2;
	user_threshold_scale  = TM_QUEUES_PER_USER;
	err_cnt               = 0;

	err_cnt += create_profile_set(&COMPANY_PROFILE_PARAMS,
				      &COMPANY_PROFILE_SET,
				      "CompanyProfiles", 0, 1, 1);

	err_cnt += create_profile_set(&COS0_PROFILE_PARAMS,
				      &COS_PROFILE_SETS[0], "ServiceClass0", 0,
				      class_shaper_scale,
				      class_threshold_scale);
	err_cnt += create_profile_set(&COS1_PROFILE_PARAMS,
				      &COS_PROFILE_SETS[1], "ServiceClass1", 0,
				      class_shaper_scale,
				      class_threshold_scale);
	err_cnt += create_profile_set(&COS2_PROFILE_PARAMS,
				      &COS_PROFILE_SETS[2], "ServiceClass2", 0,
				      class_shaper_scale,
				      class_threshold_scale);
	err_cnt += create_profile_set(&COS3_PROFILE_PARAMS,
				      &COS_PROFILE_SETS[3], "ServiceClass3", 0,
				      class_shaper_scale,
				      class_threshold_scale);

	err_cnt += create_profile_set(&COS0_PROFILE_PARAMS,
				      &USER_PROFILE_SETS[0], "UserSvc0", 0,
				      user_shaper_scale, user_threshold_scale);
	err_cnt += create_profile_set(&COS1_PROFILE_PARAMS,
				      &USER_PROFILE_SETS[1], "UserSvc1", 0,
				      user_shaper_scale, user_threshold_scale);
	err_cnt += create_profile_set(&COS2_PROFILE_PARAMS,
				      &USER_PROFILE_SETS[2], "UserSvc2", 0,
				      user_shaper_scale, user_threshold_scale);
	err_cnt += create_profile_set(&COS3_PROFILE_PARAMS,
				      &USER_PROFILE_SETS[3], "UserSvc3", 0,
				      user_shaper_scale, user_threshold_scale);

	for (app_idx = 0; app_idx < APPS_PER_USER; app_idx++) {
		err_cnt += create_profile_set(&COS0_PROFILE_PARAMS,
					      &APP_PROFILE_SETS[0][app_idx],
					      "AppSvc0", app_idx + 1, 1, 1);
		err_cnt += create_profile_set(&COS1_PROFILE_PARAMS,
					      &APP_PROFILE_SETS[1][app_idx],
					      "AppSvc1", app_idx + 1, 1, 1);
		err_cnt += create_profile_set(&COS2_PROFILE_PARAMS,
					      &APP_PROFILE_SETS[2][app_idx],
					      "AppSvc2", app_idx + 1, 1, 1);
		err_cnt += create_profile_set(&COS3_PROFILE_PARAMS,
					      &APP_PROFILE_SETS[3][app_idx],
					      "AppSvc3", app_idx + 1, 1, 1);
	}

	return err_cnt;
}

static int config_example_user(odp_tm_node_t cos_tm_node,
			       uint8_t       svc_class,
			       uint32_t      user_num)
{
	odp_tm_queue_params_t tm_queue_params;
	odp_tm_node_params_t  tm_node_params;
	odp_tm_queue_t        tm_queue;
	odp_tm_node_t         user_tm_node;
	profile_set_t        *profile_set;
	uint32_t              app_idx, queue_idx, svc_class_queue_num;
	char                  user_name[64];
	int                   rc;

	profile_set = &USER_PROFILE_SETS[svc_class];

	odp_tm_node_params_init(&tm_node_params);
	tm_node_params.max_fanin         = 64;
	tm_node_params.shaper_profile    = profile_set->shaper_profile;
	tm_node_params.threshold_profile = profile_set->threshold_profile;
	tm_node_params.wred_profile[ODP_PACKET_GREEN] =
		profile_set->wred_profiles[0];
	tm_node_params.wred_profile[ODP_PACKET_YELLOW] =
		profile_set->wred_profiles[1];
	tm_node_params.wred_profile[ODP_PACKET_RED] =
		profile_set->wred_profiles[2];
	tm_node_params.level                    = 2;

	snprintf(user_name, sizeof(user_name), "Subscriber-%" PRIu32, user_num);
	user_tm_node = odp_tm_node_create(odp_tm_test, user_name,
					  &tm_node_params);
	odp_tm_node_connect(user_tm_node, cos_tm_node);

	for (app_idx = 0; app_idx < APPS_PER_USER; app_idx++) {
		profile_set = &APP_PROFILE_SETS[svc_class][app_idx];
		for (queue_idx = 0; queue_idx < TM_QUEUES_PER_APP;
		     queue_idx++) {
			odp_tm_queue_params_init(&tm_queue_params);
			tm_queue_params.shaper_profile =
				profile_set->shaper_profile;
			tm_queue_params.threshold_profile =
				profile_set->threshold_profile;
			tm_queue_params.priority = svc_class;

			tm_queue_params.wred_profile[ODP_PACKET_GREEN] =
				profile_set->wred_profiles[ODP_PACKET_GREEN];
			tm_queue_params.wred_profile[ODP_PACKET_YELLOW] =
				profile_set->wred_profiles[ODP_PACKET_YELLOW];
			tm_queue_params.wred_profile[ODP_PACKET_RED] =
				profile_set->wred_profiles[ODP_PACKET_RED];

			tm_queue = odp_tm_queue_create(odp_tm_test,
						       &tm_queue_params);
			rc = odp_tm_queue_connect(tm_queue, user_tm_node);
			if (rc < 0)
				return rc;

			svc_class_queue_num = next_queue_nums[svc_class]++;
			queue_num_tbls[svc_class][svc_class_queue_num] =
				tm_queue;
		}
	}

	return 0;
}

static int config_company_node(const char *company_name)
{
	odp_tm_node_params_t tm_node_params;
	profile_set_t       *profile_set;
	odp_tm_node_t        company_tm_node, cos_tm_node;
	uint32_t             cos_idx, user_idx;
	char                 cos_node_name[64];

	profile_set = &COMPANY_PROFILE_SET;
	odp_tm_node_params_init(&tm_node_params);
	tm_node_params.max_fanin         = 64;
	tm_node_params.shaper_profile    = profile_set->shaper_profile;
	tm_node_params.threshold_profile = profile_set->threshold_profile;
	tm_node_params.wred_profile[ODP_PACKET_GREEN] =
		profile_set->wred_profiles[0];
	tm_node_params.wred_profile[ODP_PACKET_YELLOW] =
		profile_set->wred_profiles[1];
	tm_node_params.wred_profile[ODP_PACKET_RED] =
		profile_set->wred_profiles[2];
	tm_node_params.level                    = 0;

	company_tm_node = odp_tm_node_create(odp_tm_test, company_name,
					     &tm_node_params);

	for (cos_idx = 0; cos_idx < NUM_SVC_CLASSES; cos_idx++) {
		odp_tm_node_params_init(&tm_node_params);
		profile_set                      = &COS_PROFILE_SETS[cos_idx];
		tm_node_params.max_fanin         = 64;
		tm_node_params.shaper_profile    = profile_set->shaper_profile;
		tm_node_params.threshold_profile =
			profile_set->threshold_profile;
		tm_node_params.level             = 1;

		tm_node_params.wred_profile[ODP_PACKET_GREEN]  =
			profile_set->wred_profiles[ODP_PACKET_GREEN];
		tm_node_params.wred_profile[ODP_PACKET_YELLOW] =
			profile_set->wred_profiles[ODP_PACKET_YELLOW];
		tm_node_params.wred_profile[ODP_PACKET_RED]    =
			profile_set->wred_profiles[ODP_PACKET_RED];

		snprintf(cos_node_name, sizeof(cos_node_name),
			 "%s-Class-%" PRIu32, company_name, cos_idx);
		cos_tm_node = odp_tm_node_create(odp_tm_test, cos_node_name,
						 &tm_node_params);
		odp_tm_node_connect(cos_tm_node, company_tm_node);

		for (user_idx = 0; user_idx < USERS_PER_SVC_CLASS; user_idx++)
			config_example_user(cos_tm_node, cos_idx,
					    cos_idx * 256 + user_idx);
	}

	odp_tm_node_connect(company_tm_node, ODP_TM_ROOT);
	return 0;
}

static int create_and_config_tm(void)
{
	odp_tm_level_requirements_t *per_level;
	odp_tm_requirements_t        requirements;
	odp_tm_egress_t              egress;
	uint32_t                     level, err_cnt;

	odp_tm_requirements_init(&requirements);
	odp_tm_egress_init(&egress);

	requirements.max_tm_queues              = 10 * NUM_TM_QUEUES;
	requirements.num_levels                 = 3;
	requirements.tm_queue_shaper_needed     = true;
	requirements.tm_queue_wred_needed       = true;

	for (level = 0; level < 3; level++) {
		per_level = &requirements.per_level[level];
		per_level->max_num_tm_nodes          = MAX_NODES_PER_LEVEL;
		per_level->max_fanin_per_node        = 64;
		per_level->max_priority              = 3;
		per_level->min_weight                = 1;
		per_level->max_weight                = 255;
		per_level->tm_node_shaper_needed     = true;
		per_level->tm_node_wred_needed       = true;
		per_level->tm_node_dual_slope_needed = true;
		per_level->fair_queuing_needed       = true;
		per_level->weights_needed            = true;
	}

	egress.egress_kind = ODP_TM_EGRESS_FN;
	egress.egress_fcn  = tester_egress_fcn;

	odp_tm_test = odp_tm_create("TM test", &requirements, &egress);
	err_cnt     = init_profile_sets();
	if (err_cnt != 0)
		printf("%s init_profile_sets encountered %" PRIu32 " errors\n",
		       __func__, err_cnt);

	config_company_node("TestCompany");
	return err_cnt;
}

static uint32_t random_8(void)
{
	uint32_t rand8;

	if (RANDOM_BUF_LEN <= next_rand_byte) {
		odp_random_data(random_buf, RANDOM_BUF_LEN, 1);
		next_rand_byte = 0;
	}

	rand8 = random_buf[next_rand_byte++];
	return rand8;
}

static uint32_t random_16(void)
{
	uint8_t byte1, byte2;

	if ((RANDOM_BUF_LEN - 1) <= next_rand_byte) {
		odp_random_data(random_buf, RANDOM_BUF_LEN, 1);
		next_rand_byte = 0;
	}

	byte1 = random_buf[next_rand_byte++];
	byte2 = random_buf[next_rand_byte++];
	return (((uint16_t)byte1) << 8) | ((uint16_t)byte2);
}

static uint32_t pkt_service_class(void)
{
	uint32_t rand8;

       /* Make most of the traffic use service class 3 to increase the amount
	* of delayed traffic so as to stimulate more interesting behaviors.
	*/
	rand8 = random_8();
	switch (rand8) {
	case 0   ... 24:  return 0;
	case 25  ... 49:  return 1;
	case 50  ... 150: return 2;
	case 151 ... 255: return 3;
	default:          return 3;
	}
}

static odp_packet_t make_odp_packet(uint16_t pkt_len)
{
	odp_packet_t odp_pkt;
	uint8_t      rand8a, rand8b, pkt_color, drop_eligible;

	rand8a        = random_8();
	rand8b        = random_8();
	pkt_color     = (rand8a < 224) ? 0 : ((rand8a < 248) ? 1 : 2);
	drop_eligible = (rand8b < 240) ? 1 : 0;
	odp_pkt       = odp_packet_alloc(odp_pool, pkt_len);
	if (odp_pkt == ODP_PACKET_INVALID) {
		printf("%s odp_packet_alloc failure *******\n", __func__);
		return 0;
	}

	odp_packet_color_set(odp_pkt, pkt_color);
	odp_packet_drop_eligible_set(odp_pkt, drop_eligible);
	odp_packet_shaper_len_adjust_set(odp_pkt, 24);
	return odp_pkt;
}

void tester_egress_fcn(odp_packet_t odp_pkt ODP_UNUSED)
{
	odp_atomic_inc_u32(&atomic_pkts_from_tm);
}

static int traffic_generator(uint32_t pkts_to_send)
{
	odp_pool_param_t pool_params;
	odp_tm_queue_t   tm_queue;
	odp_packet_t     pkt;
	odp_bool_t       tm_is_idle;
	uint32_t         svc_class, queue_num, pkt_len, pkts_into_tm;
	uint32_t         pkts_from_tm, pkt_cnt, millisecs, odp_tm_enq_errs;
	int              rc;

	memset(&pool_params, 0, sizeof(odp_pool_param_t));
	pool_params.type           = ODP_POOL_PACKET;
	pool_params.pkt.num        = pkts_to_send + 10;
	pool_params.pkt.len        = 1600;
	pool_params.pkt.seg_len    = 0;
	pool_params.pkt.uarea_size = 0;

	odp_pool        = odp_pool_create("MyPktPool", &pool_params);
	odp_tm_enq_errs = 0;

	pkt_cnt = 0;
	while (pkt_cnt < pkts_to_send) {
		svc_class = pkt_service_class();
		queue_num = random_16() & (TM_QUEUES_PER_CLASS - 1);
		tm_queue  = queue_num_tbls[svc_class][queue_num];
		pkt_len   = ((uint32_t)((random_8() & 0x7F) + 2)) * 32;
		pkt_len   = MIN(pkt_len, 1500);
		pkt       = make_odp_packet(pkt_len);

		pkt_cnt++;
		rc = odp_tm_enq(tm_queue, pkt);
		if (rc < 0) {
			odp_tm_enq_errs++;
			continue;
		}

		odp_atomic_inc_u32(&atomic_pkts_into_tm);
	}

	printf("%s odp_tm_enq_errs=%" PRIu32 "\n", __func__, odp_tm_enq_errs);

       /* Wait until the main traffic mgmt worker thread is idle and has no
	* outstanding events (i.e. no timers, empty work queue, etc), but
	* not longer than 60 seconds.
	*/
	for (millisecs = 0; millisecs < 600000; millisecs++) {
		usleep(100);
		tm_is_idle = odp_tm_is_idle(odp_tm_test);
		if (tm_is_idle)
			break;
	}

	if (!tm_is_idle)
		printf("%s WARNING stopped waiting for the TM system "
		       "to be IDLE!\n", __func__);

	/* Wait for up to 2 seconds for pkts_from_tm to match pkts_into_tm. */
	for (millisecs = 0; millisecs < 2000; millisecs++) {
		usleep(1000);
		pkts_into_tm = odp_atomic_load_u32(&atomic_pkts_into_tm);
		pkts_from_tm = odp_atomic_load_u32(&atomic_pkts_from_tm);
		if (pkts_into_tm <= pkts_from_tm)
			break;
	}

	return 0;
}

static int process_cmd_line_options(uint32_t argc, char *argv[])
{
	uint32_t arg_idx;
	char    *arg;

	arg_idx = 1;
	while (arg_idx < argc) {
		arg = argv[arg_idx++];
		if (!arg) {
			return -1;
		} else if (arg[0] == '-') {
			switch (arg[1]) {
			case 'n':
				if (argc <= arg_idx)
					return -1;
				g_num_pkts_to_send =
					atoi(argv[arg_idx++]);
				break;

			case 'q':
				g_print_tm_stats = FALSE;
				break;

			default:
				printf("Unrecognized cmd line option '%s'\n",
				       arg);
				return -1;
			}
		} else {
			/* Currently all cmd line options are '-' flag based. */
			return -1;
		}
	}

	return 0;
}

static void signal_handler(int signal)
{
	size_t num_stack_frames;
	const char  *signal_name;
	void  *bt_array[128];

	switch (signal) {
	case SIGILL:
		signal_name = "SIGILL";   break;
	case SIGFPE:
		signal_name = "SIGFPE";   break;
	case SIGSEGV:
		signal_name = "SIGSEGV";  break;
	case SIGTERM:
		signal_name = "SIGTERM";  break;
	case SIGBUS:
		signal_name = "SIGBUS";   break;
	default:
		signal_name = "UNKNOWN";  break;
	}

	num_stack_frames = backtrace(bt_array, 100);
	printf("Received signal=%u (%s) exiting.", signal, signal_name);
	backtrace_symbols_fd(bt_array, num_stack_frames, fileno(stderr));
	fflush(NULL);
	sync();
	abort();
}

static int destroy_tm_queues(void)
{
	int i;
	int class;
	int ret;

	for (i = 0; i < NUM_SVC_CLASSES; i++)
		for (class = 0; class < TM_QUEUES_PER_CLASS; class++) {
			odp_tm_queue_t tm_queue;
			odp_tm_queue_info_t info;

			tm_queue = queue_num_tbls[i][class];

			ret = odp_tm_queue_info(tm_queue, &info);
			if (ret) {
				printf("Err: odp_tm_queue_info %d\n", ret);
				return -1;
			}

			ret = odp_tm_node_disconnect(info.next_tm_node);
			if (ret) {
				printf("Err: odp_tm_node_disconnect %d\n", ret);
				return -1;
			}

			ret =  odp_tm_queue_disconnect(tm_queue);
			if (ret) {
				printf("odp_tm_queue_disconnect %d\n", ret);
				return -1;
			}

			ret = odp_tm_queue_destroy(tm_queue);
			if (ret) {
				printf("odp_tm_queue_destroy %d\n", ret);
				return -1;
			}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct sigaction signal_action;
	struct rlimit    rlimit;
	uint32_t pkts_into_tm, pkts_from_tm;
	odp_instance_t instance;
	int rc;

	memset(&signal_action, 0, sizeof(signal_action));
	signal_action.sa_handler = signal_handler;
	sigfillset(&signal_action.sa_mask);
	sigaction(SIGILL,  &signal_action, NULL);
	sigaction(SIGFPE,  &signal_action, NULL);
	sigaction(SIGSEGV, &signal_action, NULL);
	sigaction(SIGTERM, &signal_action, NULL);
	sigaction(SIGBUS,  &signal_action, NULL);

	getrlimit(RLIMIT_CORE, &rlimit);
	rlimit.rlim_cur = rlimit.rlim_max;
	setrlimit(RLIMIT_CORE, &rlimit);

	rc = odp_init_global(&instance, &ODP_INIT_PARAMS, NULL);
	if (rc != 0) {
		printf("Error: odp_init_global() failed, rc = %d\n", rc);
		return -1;
	}

	rc = odp_init_local(instance, ODP_THREAD_CONTROL);
	if (rc != 0) {
		printf("Error: odp_init_local() failed, rc = %d\n", rc);
		return -1;
	}

	if (process_cmd_line_options(argc, argv) < 0)
		return -1;

	create_and_config_tm();

	odp_random_data(random_buf, RANDOM_BUF_LEN, 1);
	next_rand_byte = 0;

	odp_atomic_init_u32(&atomic_pkts_into_tm, 0);
	odp_atomic_init_u32(&atomic_pkts_from_tm, 0);

	traffic_generator(g_num_pkts_to_send);

	pkts_into_tm = odp_atomic_load_u32(&atomic_pkts_into_tm);
	pkts_from_tm = odp_atomic_load_u32(&atomic_pkts_from_tm);
	printf("pkts_into_tm=%" PRIu32 " pkts_from_tm=%" PRIu32 "\n",
	       pkts_into_tm, pkts_from_tm);

	odp_tm_stats_print(odp_tm_test);

	rc = destroy_tm_queues();
	if (rc != 0) {
		printf("Error: destroy_tm_queues() failed, rc = %d\n", rc);
		return -1;
	}

	rc = odp_pool_destroy(odp_pool);
	if (rc != 0) {
		printf("Error: odp_pool_destroy() failed, rc = %d\n", rc);
		return -1;
	}

	rc = odp_tm_destroy(odp_tm_test);
	if (rc != 0) {
		printf("Error: odp_tm_destroy() failed, rc = %d\n", rc);
		return -1;
	}

	rc = odp_term_local();
	if (rc != 0) {
		printf("Error: odp_term_local() failed, rc = %d\n", rc);
		return -1;
	}

	rc = odp_term_global(instance);
	if (rc != 0) {
		printf("Error: odp_term_global() failed, rc = %d\n", rc);
		return -1;
	}

	printf("Quit\n");
	return 0;
}
