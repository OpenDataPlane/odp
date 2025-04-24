/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2020-2025 Nokia
 *
 * Copyright(c) 2010-2014 Intel Corporation
 *   - lib/eal/common/eal_common_string_fns.c
 *   - lib/eal/linux/eal_hugepage_info.c
 */

#include <odp_posix_extensions.h>

#include <odp/api/align.h>
#include <odp/api/cpu.h>
#include <odp/api/hints.h>
#include <odp/api/system_info.h>
#include <odp/api/version.h>

#include <odp_global_data.h>
#include <odp_sysinfo_internal.h>
#include <odp_init_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_debug_internal.h>
#include <odp_config_internal.h>

#include <errno.h>
#include <limits.h>
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
 * Analysis of /sys/devices/system/cpu/ files
 */
static int read_cache_line_size(void)
{
	FILE  *file;
	char str[128];
	int size = 0;

	file = fopen(CACHE_LNSZ_FILE, "rt");
	if (file == NULL) {
		/* File not found */
		_ODP_WARN("Unable to read host CPU cache line size. "
			  "Using ODP_CACHE_LINE_SIZE instead.\n");
		return ODP_CACHE_LINE_SIZE;
	}

	if (fgets(str, sizeof(str), file) != NULL) {
		/* Read cache line size */
		if (sscanf(str, "%i", &size) != 1)
			size = 0;
	}

	fclose(file);

	return size;
}

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
			_ODP_DBG("default hp size is %lu kB\n", sz);
			fclose(file);
			return (uint64_t)sz * 1024;
		}
	}

	_ODP_ERR("unable to get default hp size\n");
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
			_ODP_ERR("Error parsing %s\n", proc_mounts);
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
			} else {
				/* there is an explicit page size, so check it */
				pagesz = str_to_size(&pagesz_str[pagesize_opt_len]);
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
	char path[256], buffer[256];
	FILE *file;
	uint64_t ret = 0;

	snprintf(path, sizeof(path),
		 "/sys/devices/system/cpu/cpu%d/cpufreq/%s", id, filename);

	file = fopen(path, "r");
	if (file == NULL)
		return ret;

	if (fgets(buffer, sizeof(buffer), file) != NULL) {
		errno = 0;
		ret = strtoull(buffer, NULL, 10);
		if (errno) {
			_ODP_ERR("Out of range CPU frequency from %s\n", path);
			ret = 0;
		} else {
			ret *= 1000;
		}
	}

	fclose(file);

	return ret;
}

static inline uint64_t cpu_hz_current(int id)
{
	uint64_t cur_hz = read_cpufreq("cpuinfo_cur_freq", id);

	if (!cur_hz)
		cur_hz = odp_cpu_arch_hz_current(id);

	return cur_hz;
}

static inline uint64_t cpu_hz_static(int id)
{
	return odp_global_ro.system_info.cpu_hz[id];
}

/*
 * Analysis of /sys/devices/system/cpu/ files
 */
static int system_cache_line(system_info_t *sysinfo)
{
	int ret;

	ret = read_cache_line_size();
	if (ret == 0) {
		_ODP_ERR("read_cache_line_size failed.\n");
		return -1;
	}

	sysinfo->cache_line_size = ret;

	if (ret != ODP_CACHE_LINE_SIZE)
		_ODP_WARN("Host CPU cache line size and ODP_CACHE_LINE_SIZE don't match.\n");

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

static int read_config_file(void)
{
	const char *str;
	int val = 0;

	str = "system.cpu_mhz";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	odp_global_ro.system_info.default_cpu_hz = (uint64_t)val * 1000000;

	str = "system.cpu_mhz_max";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	odp_global_ro.system_info.default_cpu_hz_max = (uint64_t)val * 1000000;

	str = "system.cpu_hz_static";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	odp_global_ro.system_info.cpu_hz_static = !!val;

	_ODP_PRINT("System config:\n");
	_ODP_PRINT("  system.cpu_mhz: %" PRIu64 "\n",
		   odp_global_ro.system_info.default_cpu_hz);
	_ODP_PRINT("  system.cpu_mhz_max: %" PRIu64 "\n",
		   odp_global_ro.system_info.default_cpu_hz_max);
	_ODP_PRINT("  system.cpu_hz_static: %" PRIu8 "\n\n",
		   odp_global_ro.system_info.cpu_hz_static);

	return 0;
}

static void print_compiler_info(void)
{
	_ODP_PRINT("Compiler defines:\n");
	_ODP_PRINT("  __GCC_ATOMIC_LLONG_LOCK_FREE:        %d\n", __GCC_ATOMIC_LLONG_LOCK_FREE);
	_ODP_PRINT("  __GCC_ATOMIC_LONG_LOCK_FREE:         %d\n", __GCC_ATOMIC_LONG_LOCK_FREE);
	_ODP_PRINT("  __GCC_ATOMIC_INT_LOCK_FREE:          %d\n", __GCC_ATOMIC_INT_LOCK_FREE);
	_ODP_PRINT("  __GCC_HAVE_SYNC_COMPARE_AND_SWAP_16: ");
#ifdef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_16
	_ODP_PRINT("1\n");
#else
	_ODP_PRINT("0\n");
#endif
	_ODP_PRINT("\n");
}

/*
 * System info initialisation
 */
int _odp_system_info_init(void)
{
	int num_cpus;
	int i;
	FILE  *file;

	memset(&odp_global_ro.system_info, 0, sizeof(system_info_t));

	odp_global_ro.system_info.page_size = ODP_PAGE_SIZE;

	/* Read default CPU Hz values from config file */
	if (read_config_file())
		return -1;

	/* Check that CONFIG_NUM_CPU_IDS is large enough */
	num_cpus = get_nprocs_conf();
	if (num_cpus > CONFIG_NUM_CPU_IDS)
		_ODP_ERR("Unable to handle all %d "
			"CPU IDs. Increase CONFIG_NUM_CPU_IDS value.\n",
			num_cpus);

	/* Read and save all CPU frequencies for static mode */
	if (odp_global_ro.system_info.cpu_hz_static)
		for (i = 0; i < CONFIG_NUM_CPU_IDS; i++)
			odp_global_ro.system_info.cpu_hz[i] = cpu_hz_current(i);

	/* By default, read max frequency from a cpufreq file */
	for (i = 0; i < CONFIG_NUM_CPU_IDS; i++) {
		uint64_t cpu_hz_max = read_cpufreq("cpuinfo_max_freq", i);

		if (cpu_hz_max)
			odp_global_ro.system_info.cpu_hz_max[i] = cpu_hz_max;
	}

	file = fopen("/proc/cpuinfo", "rt");
	if (file != NULL) {
		/* Read CPU model, and set max cpu frequency
		 * if not set from cpufreq. */
		_odp_cpuinfo_parser(file, &odp_global_ro.system_info);
		fclose(file);
	} else {
		_odp_dummy_cpuinfo(&odp_global_ro.system_info);
	}

	if (system_cache_line(&odp_global_ro.system_info))
		return -1;

	system_hp(&odp_global_ro.hugepage_info);

	print_compiler_info();

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
uint64_t odp_cpu_hz(void)
{
	int id = odp_cpu_id();

	if (odp_unlikely(id < 0))
		return -1;

	if (odp_global_ro.system_info.cpu_hz_static)
		return cpu_hz_static(id);
	return cpu_hz_current(id);
}

uint64_t odp_cpu_hz_id(int id)
{
	_ODP_ASSERT(id >= 0 && id < CONFIG_NUM_CPU_IDS);

	if (odp_global_ro.system_info.cpu_hz_static)
		return cpu_hz_static(id);
	return cpu_hz_current(id);
}

uint64_t odp_cpu_hz_max(void)
{
	return odp_cpu_hz_max_id(0);
}

uint64_t odp_cpu_hz_max_id(int id)
{
	if (id >= 0 && id < CONFIG_NUM_CPU_IDS)
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
	const uint64_t val1 = *(const uint64_t *)pagesz1;
	const uint64_t val2 = *(const uint64_t *)pagesz2;

	if (val1 < val2)
		return -1;
	if (val1 > val2)
		return 1;
	return 0;
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
		_ODP_PRINT("Failed to open /sys/kernel/mm/hugepages: %s\n", strerror(errno));
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
	if (id >= 0 && id < CONFIG_NUM_CPU_IDS)
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
	return odp_global_ro.num_cpus_installed;
}

int odp_system_info(odp_system_info_t *info)
{
	system_info_t *sys_info = &odp_global_ro.system_info;

	memset(info, 0, sizeof(odp_system_info_t));

	info->cpu_arch   = sys_info->cpu_arch;
	info->cpu_isa_sw = sys_info->cpu_isa_sw;
	info->cpu_isa_hw = sys_info->cpu_isa_hw;

	return 0;
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
	_ODP_PRINT("%s", str);

	_odp_sys_info_print_arch();
}

void odp_sys_config_print(void)
{
	/* Print ODP_CONFIG_FILE default and override values */
	if (_odp_libconfig_print())
		_ODP_ERR("Config file print failed\n");

	_ODP_PRINT("\n\nodp_config_internal.h values:\n"
		  "-----------------------------\n");
	_ODP_PRINT("CONFIG_NUM_CPU_IDS:            %i\n", CONFIG_NUM_CPU_IDS);
	_ODP_PRINT("CONFIG_INTERNAL_QUEUES:        %i\n", CONFIG_INTERNAL_QUEUES);
	_ODP_PRINT("CONFIG_MAX_PLAIN_QUEUES:       %i\n", CONFIG_MAX_PLAIN_QUEUES);
	_ODP_PRINT("CONFIG_MAX_SCHED_QUEUES:       %i\n", CONFIG_MAX_SCHED_QUEUES);
	_ODP_PRINT("CONFIG_MAX_QUEUES:             %i\n", CONFIG_MAX_QUEUES);
	_ODP_PRINT("CONFIG_QUEUE_MAX_ORD_LOCKS:    %i\n", CONFIG_QUEUE_MAX_ORD_LOCKS);
	_ODP_PRINT("CONFIG_MAX_DMA_SESSIONS:       %i\n", CONFIG_MAX_DMA_SESSIONS);
	_ODP_PRINT("CONFIG_INTERNAL_STASHES:       %i\n", CONFIG_INTERNAL_STASHES);
	_ODP_PRINT("CONFIG_MAX_STASHES:            %i\n", CONFIG_MAX_STASHES);
	_ODP_PRINT("CONFIG_PKTIO_ENTRIES:          %i\n", CONFIG_PKTIO_ENTRIES);
	_ODP_PRINT("CONFIG_BUFFER_ALIGN_MAX:       %i\n", CONFIG_BUFFER_ALIGN_MAX);
	_ODP_PRINT("CONFIG_PACKET_HEADROOM:        %i\n", CONFIG_PACKET_HEADROOM);
	_ODP_PRINT("CONFIG_PACKET_TAILROOM:        %i\n", CONFIG_PACKET_TAILROOM);
	_ODP_PRINT("CONFIG_PACKET_SEG_SIZE:        %i\n", CONFIG_PACKET_SEG_SIZE);
	_ODP_PRINT("CONFIG_PACKET_MAX_SEG_LEN:     %i\n", CONFIG_PACKET_MAX_SEG_LEN);
	_ODP_PRINT("CONFIG_PACKET_SEG_LEN_MIN:     %i\n", CONFIG_PACKET_SEG_LEN_MIN);
	_ODP_PRINT("CONFIG_PACKET_VECTOR_MAX_SIZE: %i\n", CONFIG_PACKET_VECTOR_MAX_SIZE);
	_ODP_PRINT("CONFIG_EVENT_VECTOR_MAX_SIZE:  %i\n", CONFIG_EVENT_VECTOR_MAX_SIZE);
	_ODP_PRINT("CONFIG_INTERNAL_SHM_BLOCKS:    %i\n", CONFIG_INTERNAL_SHM_BLOCKS);
	_ODP_PRINT("CONFIG_SHM_BLOCKS:             %i\n", CONFIG_SHM_BLOCKS);
	_ODP_PRINT("CONFIG_BURST_SIZE:             %i\n", CONFIG_BURST_SIZE);
	_ODP_PRINT("CONFIG_INTERNAL_POOLS:         %i\n", CONFIG_INTERNAL_POOLS);
	_ODP_PRINT("CONFIG_POOLS:                  %i\n", CONFIG_POOLS);
	_ODP_PRINT("CONFIG_POOL_MAX_NUM:           %i\n", CONFIG_POOL_MAX_NUM);
	_ODP_PRINT("CONFIG_POOL_CACHE_MAX_SIZE:    %i\n", CONFIG_POOL_CACHE_MAX_SIZE);
	_ODP_PRINT("CONFIG_POOL_STATISTICS:        %i\n", CONFIG_POOL_STATISTICS);
	_ODP_PRINT("CONFIG_IPSEC_MAX_NUM_SA:       %i\n", CONFIG_IPSEC_MAX_NUM_SA);
	_ODP_PRINT("CONFIG_TIMER_128BIT_ATOMICS:   %i\n", CONFIG_TIMER_128BIT_ATOMICS);
	_ODP_PRINT("CONFIG_TIMER_PROFILE_INLINE:   %i\n", CONFIG_TIMER_PROFILE_INLINE);
	_ODP_PRINT("CONFIG_ML_MAX_MODELS:          %i\n", CONFIG_ML_MAX_MODELS);
	_ODP_PRINT("CONFIG_ML_MAX_INPUTS:          %i\n", CONFIG_ML_MAX_INPUTS);
	_ODP_PRINT("CONFIG_ML_MAX_OUTPUTS:         %i\n", CONFIG_ML_MAX_OUTPUTS);
	_ODP_PRINT("\n");
}
