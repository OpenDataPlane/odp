/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <odp_api.h>
#include <store.h>
#include <sample.h>
#include <papi_cnt.h>

#define SAMPLE_TAB_SIZE 50000

static __thread profiling_sample_t profile_sample_tab[SAMPLE_TAB_SIZE];
static __thread uint64_t profile_sample_idx;
static __thread uint64_t profile_sample_ovf;

#define STORE_DIR_ENV "ODP_INSTRUM_STORE_DIR"
#define STORE_DIR_NAME_DFLT "/tmp"
#define STORE_DIR_NAME_SIZE_MAX 250
#define STORE_FILE_NAME_SIZE_MAX 250

static char store_dir[STORE_DIR_NAME_SIZE_MAX];

static void store_dump(int last)
{
	FILE *f = NULL;
	char file_name[STORE_DIR_NAME_SIZE_MAX + STORE_FILE_NAME_SIZE_MAX];
	char smpl[250], smpl_tmp[250];
	int i, j, dump_size = SAMPLE_TAB_SIZE;

	if (last)
		dump_size = profile_sample_idx;

	sprintf(file_name, "%s/profile_%d_%ju.csv",
		store_dir, odp_thread_id(),
		profile_sample_ovf);

	f = fopen(file_name, "w");
	if (f == NULL) {
		printf("Failed to create profiling file %s\n", file_name);
		return;
	}

	for (i = 0; i < dump_size; i++) {
		sprintf(smpl, "%lld,%lld,%s",
			profile_sample_tab[i].timestamp_ns,
			profile_sample_tab[i].diff_cyc,
			profile_sample_tab[i].name);
		for (j = 0; j < SAMPLE_COUNTER_TAB_SIZE; j++) {
			sprintf(smpl_tmp, ",%lld",
				profile_sample_tab[i].counters[j]);
			strcat(smpl, smpl_tmp);
		}
		fprintf(f, "%s\n", smpl);
	}

	fclose(f);
}

int instr_store_init(void)
{
	const char *store_dir_env = NULL;

	store_dir_env = getenv(STORE_DIR_ENV);
	if (!store_dir_env)
		store_dir_env = STORE_DIR_NAME_DFLT;

	strncpy(store_dir, store_dir_env, STORE_DIR_NAME_SIZE_MAX);
	store_dir[STORE_DIR_NAME_SIZE_MAX - 1] = '\0';

	if (papi_init())
		return -1;

	return 0;
}

void instr_store_term(void)
{
	papi_term();
}

int instr_store_init_local(void)
{
	return papi_init_local();
}

int instr_store_term_local(void)
{
	int ret = papi_term_local();

	store_dump(1);

	return ret;
}

instr_profiling_sample_t store_sample_start(const char *func)
{
	profiling_sample_t *spl = NULL;

	if (profile_sample_idx == SAMPLE_TAB_SIZE)
		return NULL;

	spl = &profile_sample_tab[profile_sample_idx];

	strncpy(spl->name, func, SAMPLE_NAME_SIZE_MAX);
	spl->name[SAMPLE_NAME_SIZE_MAX - 1] = '\0';

	if (papi_sample_start(spl))
		return NULL;

	profile_sample_idx++;
	return spl;
}

void store_sample_end(instr_profiling_sample_t _spl)
{
	profiling_sample_t *spl = _spl;

	if (!spl) /* failed sample - on start */
		return;

	if (papi_sample_end(spl))
		spl->name[0] = 0; /* failed sample - on end*/

	if (profile_sample_idx == SAMPLE_TAB_SIZE) {
		store_dump(0);
		profile_sample_idx = 0;
		profile_sample_ovf++;
	}
}
