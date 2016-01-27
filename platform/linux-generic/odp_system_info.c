/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp/system_info.h>
#include <odp_internal.h>
#include <odp_debug_internal.h>
#include <odp/align.h>
#include <odp/cpu.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>

/* sysconf */
#include <unistd.h>
#include <sys/sysinfo.h>

/* opendir, readdir */
#include <sys/types.h>
#include <dirent.h>


#define CACHE_LNSZ_FILE \
	"/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size"

#define HUGE_PAGE_DIR "/sys/kernel/mm/hugepages"


/*
 * Report the number of CPUs in the affinity mask of the main thread
 */
static int sysconf_cpu_count(void)
{
	cpu_set_t cpuset;
	int ret;

	ret = pthread_getaffinity_np(pthread_self(),
				     sizeof(cpuset), &cpuset);
	if (ret != 0)
		return 0;

	return CPU_COUNT(&cpuset);
}

#if defined __x86_64__ || defined __i386__ || defined __OCTEON__ || \
defined __powerpc__
/*
 * Analysis of /sys/devices/system/cpu/ files
 */
static int systemcpu_cache_line_size(void)
{
	FILE  *file;
	char str[128];
	int size = 0;

	file = fopen(CACHE_LNSZ_FILE, "rt");
	if (file == NULL) {
		/* File not found */
		return 0;
	}

	if (fgets(str, sizeof(str), file) != NULL) {
		/* Read cache line size */
		sscanf(str, "%i", &size);
	}

	fclose(file);

	return size;
}
#endif


static int huge_page_size(void)
{
	DIR *dir;
	struct dirent *dirent;
	int size = 0;

	dir = opendir(HUGE_PAGE_DIR);
	if (dir == NULL) {
		ODP_ERR("%s not found\n", HUGE_PAGE_DIR);
		return 0;
	}

	while ((dirent = readdir(dir)) != NULL) {
		int temp = 0;
		sscanf(dirent->d_name, "hugepages-%i", &temp);

		if (temp > size)
			size = temp;
	}

	if (closedir(dir)) {
		ODP_ERR("closedir failed\n");
		return 0;
	}

	return size*1024;
}



/*
 * HW specific /proc/cpuinfo file parsing
 */
#if defined __arm__ || defined __aarch64__

static int odp_cpuinfo_parser(FILE *file ODP_UNUSED,
			      odp_system_info_t *sysinfo ODP_UNUSED)
{
	return 0;
}

static uint64_t odp_cpu_hz_current(int id ODP_UNUSED)
{
	return -1;
}

#elif defined __powerpc__
static int odp_cpuinfo_parser(FILE *file, odp_system_info_t *sysinfo)
{
	char str[1024];
	char *pos;
	double mhz = 0.0;
	int model = 0;
	int count = 2;

	while (fgets(str, sizeof(str), file) != NULL && count > 0) {
		if (!mhz) {
			pos = strstr(str, "clock");

			if (pos) {
				sscanf(pos, "clock : %lf", &mhz);
				count--;
			}
		}

		if (!model) {
			pos = strstr(str, "cpu");

			if (pos) {
				int len;
				pos = strchr(str, ':');
				strncpy(sysinfo->model_str[0], pos + 2,
					sizeof(sysinfo->model_str[0]));
				len = strlen(sysinfo->model_str[0]);
				sysinfo->model_str[0][len - 1] = 0;
				model = 1;
				count--;
			}
		}

		sysinfo->cpu_hz[0] = (uint64_t)(mhz * 1000000.0);
	}


	return 0;
}

static uint64_t odp_cpu_hz_current(int id ODP_UNUSED)
{
	return -1;
}

#endif


#if defined __x86_64__ || defined __i386__ || defined __OCTEON__ || \
defined __powerpc__

/*
 * Analysis of /sys/devices/system/cpu/ files
 */
static int systemcpu(odp_system_info_t *sysinfo)
{
	int ret;

	ret = sysconf_cpu_count();
	if (ret == 0) {
		ODP_ERR("sysconf_cpu_count failed.\n");
		return -1;
	}

	sysinfo->cpu_count = ret;


	ret = systemcpu_cache_line_size();
	if (ret == 0) {
		ODP_ERR("systemcpu_cache_line_size failed.\n");
		return -1;
	}

	sysinfo->cache_line_size = ret;

	if (ret != ODP_CACHE_LINE_SIZE) {
		ODP_ERR("Cache line sizes definitions don't match.\n");
		return -1;
	}

	odp_global_data.system_info.huge_page_size = huge_page_size();

	return 0;
}

#else

/*
 * Use sysconf and dummy values in generic case
 */


static int systemcpu(odp_system_info_t *sysinfo)
{
	int ret;

	ret = sysconf_cpu_count();
	if (ret == 0) {
		ODP_ERR("sysconf_cpu_count failed.\n");
		return -1;
	}

	sysinfo->cpu_count = ret;

	sysinfo->huge_page_size = huge_page_size();

	/* Dummy values */
	sysinfo->cpu_hz[0]       = 1400000000;
	sysinfo->cache_line_size = 64;

	strncpy(sysinfo->model_str[0], "UNKNOWN", sizeof(sysinfo->model_str));

	return 0;
}

#endif

/*
 * System info initialisation
 */
int odp_system_info_init(void)
{
	FILE  *file;

	memset(&odp_global_data.system_info, 0, sizeof(odp_system_info_t));

	odp_global_data.system_info.page_size = ODP_PAGE_SIZE;

	file = fopen("/proc/cpuinfo", "rt");
	if (file == NULL) {
		ODP_ERR("Failed to open /proc/cpuinfo\n");
		return -1;
	}

	odp_cpuinfo_parser(file, &odp_global_data.system_info);

	fclose(file);

	if (systemcpu(&odp_global_data.system_info)) {
		ODP_ERR("systemcpu failed\n");
		return -1;
	}

	return 0;
}

/*
 * System info termination
 */
int odp_system_info_term(void)
{
	return 0;
}

/*
 *************************
 * Public access functions
 *************************
 */
uint64_t odp_cpu_hz(void)
{
	int id = sched_getcpu();

	return odp_cpu_hz_current(id);
}

uint64_t odp_cpu_hz_id(int id)
{
	return odp_cpu_hz_current(id);
}

uint64_t odp_cpu_hz_max(void)
{
	return odp_cpu_hz_max_id(0);
}

uint64_t odp_cpu_hz_max_id(int id)
{
	if (id >= 0 && id < MAX_CPU_NUMBER)
		return odp_global_data.system_info.cpu_hz[id];
	else
		return -1;
}

uint64_t odp_sys_huge_page_size(void)
{
	return odp_global_data.system_info.huge_page_size;
}

uint64_t odp_sys_page_size(void)
{
	return odp_global_data.system_info.page_size;
}

const char *odp_cpu_model_str(void)
{
	return odp_cpu_model_str_id(0);
}

const char *odp_cpu_model_str_id(int id)
{
	if (id >= 0 && id < MAX_CPU_NUMBER)
		return odp_global_data.system_info.model_str[id];
	else
		return NULL;
}

int odp_sys_cache_line_size(void)
{
	return odp_global_data.system_info.cache_line_size;
}

int odp_cpu_count(void)
{
	return odp_global_data.system_info.cpu_count;
}
