/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 */

#include <odp_posix_extensions.h>

#include <odp/api/system_info.h>
#include <odp/api/version.h>
#include <odp_global_data.h>
#include <odp_sysinfo_internal.h>
#include <odp_init_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/align.h>
#include <odp/api/cpu.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <ctype.h>

/* sysconf */
#include <unistd.h>
#include <sys/sysinfo.h>

/* opendir, readdir */
#include <sys/types.h>
#include <dirent.h>

#define CACHE_LNSZ_FILE \
	"/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size"

/*
 * Report the number of logical CPUs detected at boot time
 */
static int sysconf_cpu_count(void)
{
	return odp_global_ro.num_cpus_installed;
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
		if (sscanf(str, "%i", &size) != 1)
			size = 0;
	}

	fclose(file);

	return size;
}

#else
/*
 * Use dummy data if not available from /sys/devices/system/cpu/
 */
static int systemcpu_cache_line_size(void)
{
	return 64;
}
#endif


static uint64_t default_huge_page_size(void)
{
	char str[1024];
	unsigned long sz;
	FILE *file;

	file = fopen("/proc/meminfo", "rt");
	if (!file)
		return 0;

	while (fgets(str, sizeof(str), file) != NULL) {
		if (sscanf(str, "Hugepagesize:   %8lu kB", &sz) == 1) {
			ODP_DBG("defaut hp size is %" PRIu64 " kB\n", sz);
			fclose(file);
			return (uint64_t)sz * 1024;
		}
	}

	ODP_ERR("unable to get default hp size\n");
	fclose(file);
	return 0;
}

/*
 * split string into tokens. largely "inspired" by dpdk:
 * lib/librte_eal/common/eal_common_string_fns.c: rte_strsplit
 */
static int strsplit(char *string, int stringlen,
		    char **tokens, int maxtokens, char delim)
{
	int i, tok = 0;
	int tokstart = 1; /* first token is right at start of string */

	if (string == NULL || tokens == NULL)
		return -1;

	for (i = 0; i < stringlen; i++) {
		if (string[i] == '\0' || tok >= maxtokens)
			break;
		if (tokstart) {
			tokstart = 0;
			tokens[tok++] = &string[i];
		}
		if (string[i] == delim) {
			string[i] = '\0';
			tokstart = 1;
		}
	}
	return tok;
}

/*
 * Converts a numeric string to the equivalent uint64_t value.
 * As well as straight number conversion, also recognises the suffixes
 * k, m and g for kilobytes, megabytes and gigabytes respectively.
 *
 * If a negative number is passed in  i.e. a string with the first non-black
 * character being "-", zero is returned. Zero is also returned in the case of
 * an error with the strtoull call in the function.
 * largely "inspired" by dpdk:
 * lib/librte_eal/common/include/rte_common.h: rte_str_to_size
 *
 * param str
 *     String containing number to convert.
 * return
 *     Number.
 */
static inline uint64_t str_to_size(const char *str)
{
	char *endptr;
	unsigned long long size;

	while (isspace((int)*str))
		str++;
	if (*str == '-')
		return 0;

	errno = 0;
	size = strtoull(str, &endptr, 0);
	if (errno)
		return 0;

	if (*endptr == ' ')
		endptr++; /* allow 1 space gap */

	switch (*endptr) {
	case 'G':
	case 'g':
		size *= 1024; /* fall-through */
	case 'M':
	case 'm':
		size *= 1024; /* fall-through */
	case 'K':
	case 'k':
		size *= 1024; /* fall-through */
	default:
		break;
	}
	return size;
}

/*
 * returns a malloced string containing the name of the directory for
 * huge pages of a given size (0 for default)
 * largely "inspired" by dpdk:
 * lib/librte_eal/linuxapp/eal/eal_hugepage_info.c: get_hugepage_dir
 *
 * Analysis of /proc/mounts
 */
static char *get_hugepage_dir(uint64_t hugepage_sz)
{
	enum proc_mount_fieldnames {
		DEVICE = 0,
		MOUNTPT,
		FSTYPE,
		OPTIONS,
		_FIELDNAME_MAX
	};
	static uint64_t default_size;
	const char proc_mounts[] = "/proc/mounts";
	const char hugetlbfs_str[] = "hugetlbfs";
	const size_t htlbfs_str_len = sizeof(hugetlbfs_str) - 1;
	const char pagesize_opt[] = "pagesize=";
	const size_t pagesize_opt_len = sizeof(pagesize_opt) - 1;
	const char split_tok = ' ';
	char *tokens[_FIELDNAME_MAX];
	char buf[BUFSIZ];
	char *retval = NULL;
	const char *pagesz_str;
	uint64_t pagesz;
	FILE *fd = fopen(proc_mounts, "r");

	if (fd == NULL)
		return NULL;

	if (default_size == 0)
		default_size = default_huge_page_size();

	if (hugepage_sz == 0)
		hugepage_sz = default_size;

	while (fgets(buf, sizeof(buf), fd)) {
		if (strsplit(buf, sizeof(buf), tokens,
			     _FIELDNAME_MAX, split_tok) != _FIELDNAME_MAX) {
			ODP_ERR("Error parsing %s\n", proc_mounts);
			break; /* return NULL */
		}

		/* is this hugetlbfs? */
		if (!strncmp(tokens[FSTYPE], hugetlbfs_str, htlbfs_str_len)) {
			pagesz_str = strstr(tokens[OPTIONS], pagesize_opt);

			/* No explicit size, default page size is compared */
			if (pagesz_str == NULL) {
				if (hugepage_sz == default_size) {
					retval = strdup(tokens[MOUNTPT]);
					break;
				}
			}
			/* there is an explicit page size, so check it */
			else {
				pagesz =
				     str_to_size(&pagesz_str[pagesize_opt_len]);
				if (pagesz == hugepage_sz) {
					retval = strdup(tokens[MOUNTPT]);
					break;
				}
			}
		} /* end if strncmp hugetlbfs */
	} /* end while fgets */

	fclose(fd);
	return retval;
}

/*
 * Analysis of /sys/devices/system/cpu/cpu%d/cpufreq/ files
 */
static uint64_t read_cpufreq(const char *filename, int id)
{
	char path[256], buffer[256], *endptr = NULL;
	FILE *file;
	uint64_t ret = 0;

	snprintf(path, sizeof(path),
		 "/sys/devices/system/cpu/cpu%d/cpufreq/%s", id, filename);

	file = fopen(path, "r");
	if (file == NULL)
		return ret;

	if (fgets(buffer, sizeof(buffer), file) != NULL)
		ret = strtoull(buffer, &endptr, 0) * 1000;

	fclose(file);

	return ret;
}

/*
 * Analysis of /sys/devices/system/cpu/ files
 */
static int systemcpu(system_info_t *sysinfo)
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

	return 0;
}

/*
 * Huge page information
 */
static int system_hp(hugepage_info_t *hugeinfo)
{
	hugeinfo->default_huge_page_size = default_huge_page_size();

	/* default_huge_page_dir may be NULL if no huge page support */
	hugeinfo->default_huge_page_dir = get_hugepage_dir(0);

	return 0;
}

/*
 * System info initialisation
 */
int _odp_system_info_init(void)
{
	int i;
	FILE  *file;

	memset(&odp_global_ro.system_info, 0, sizeof(system_info_t));

	odp_global_ro.system_info.page_size = ODP_PAGE_SIZE;

	/* By default, read max frequency from a cpufreq file */
	for (i = 0; i < CONFIG_NUM_CPU; i++) {
		uint64_t cpu_hz_max = read_cpufreq("cpuinfo_max_freq", i);

		if (cpu_hz_max)
			odp_global_ro.system_info.cpu_hz_max[i] = cpu_hz_max;
	}

	file = fopen("/proc/cpuinfo", "rt");
	if (file != NULL) {
		/* Read CPU model, and set max cpu frequency
		 * if not set from cpufreq. */
		cpuinfo_parser(file, &odp_global_ro.system_info);
		fclose(file);
	} else {
		_odp_dummy_cpuinfo(&odp_global_ro.system_info);
	}

	if (systemcpu(&odp_global_ro.system_info)) {
		ODP_ERR("systemcpu failed\n");
		return -1;
	}

	system_hp(&odp_global_ro.hugepage_info);

	return 0;
}

/*
 * System info termination
 */
int _odp_system_info_term(void)
{
	free(odp_global_ro.hugepage_info.default_huge_page_dir);

	return 0;
}

/*
 *************************
 * Public access functions
 *************************
 */
uint64_t odp_cpu_hz_current(int id)
{
	uint64_t cur_hz = read_cpufreq("cpuinfo_cur_freq", id);

	if (!cur_hz)
		cur_hz = odp_cpu_arch_hz_current(id);

	return cur_hz;
}

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
	if (id >= 0 && id < CONFIG_NUM_CPU)
		return odp_global_ro.system_info.cpu_hz_max[id];
	else
		return 0;
}

uint64_t odp_sys_huge_page_size(void)
{
	return odp_global_ro.hugepage_info.default_huge_page_size;
}

static int pagesz_compare(const void *pagesz1, const void *pagesz2)
{
	return (*(const uint64_t *)pagesz1 - *(const uint64_t *)pagesz2);
}

int odp_sys_huge_page_size_all(uint64_t size[], int num)
{
	DIR *dir;
	struct dirent *entry;
	int pagesz_num = 0;
	int saved = 0;

	/* See: kernel.org: hugetlbpage.txt */
	dir = opendir("/sys/kernel/mm/hugepages");
	if (!dir) {
		ODP_PRINT("Failed to open /sys/kernel/mm/hugepages: %s\n",
			  strerror(errno));
		return 0;
	}

	while ((entry = readdir(dir)) != NULL) {
		unsigned long sz;

		if (sscanf(entry->d_name, "hugepages-%8lukB", &sz) == 1) {
			if (size != NULL && saved < num)
				size[saved++] = sz * 1024;
			pagesz_num++;
		}
	}
	closedir(dir);

	if (size != NULL && saved > 1)
		qsort(size, saved, sizeof(uint64_t), pagesz_compare);

	return pagesz_num;
}

uint64_t odp_sys_page_size(void)
{
	return odp_global_ro.system_info.page_size;
}

const char *odp_cpu_model_str(void)
{
	return odp_cpu_model_str_id(0);
}

const char *odp_cpu_model_str_id(int id)
{
	if (id >= 0 && id < CONFIG_NUM_CPU)
		return odp_global_ro.system_info.model_str[id];
	else
		return NULL;
}

int odp_sys_cache_line_size(void)
{
	return odp_global_ro.system_info.cache_line_size;
}

int odp_cpu_count(void)
{
	return odp_global_ro.system_info.cpu_count;
}

void odp_sys_info_print(void)
{
	int len, num_cpu;
	int max_len = 512;
	odp_cpumask_t cpumask;
	char cpumask_str[ODP_CPUMASK_STR_SIZE];
	char str[max_len];

	memset(cpumask_str, 0, sizeof(cpumask_str));

	num_cpu = odp_cpumask_all_available(&cpumask);
	odp_cpumask_to_str(&cpumask, cpumask_str, ODP_CPUMASK_STR_SIZE);

	len = snprintf(str, max_len, "\n"
		       "ODP system info\n"
		       "---------------\n"
		       "ODP API version:  %s\n"
		       "ODP impl name:    %s\n"
		       "ODP impl details: %s\n"
		       "CPU model:        %s\n"
		       "CPU freq (hz):    %" PRIu64 "\n"
		       "Cache line size:  %i\n"
		       "CPU count:        %i\n"
		       "CPU mask:         %s\n"
		       "\n",
		       odp_version_api_str(),
		       odp_version_impl_name(),
		       odp_version_impl_str(),
		       odp_cpu_model_str(),
		       odp_cpu_hz_max(),
		       odp_sys_cache_line_size(),
		       num_cpu, cpumask_str);

	str[len] = '\0';
	ODP_PRINT("%s", str);

	sys_info_print_arch();
}
