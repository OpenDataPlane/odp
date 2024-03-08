/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2020-2021 Nokia
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <odp/api/hints.h>
#include <odp_global_data.h>
#include <odp_sysinfo_internal.h>
#include <odp_debug_internal.h>
#include "cpu_flags.h"

#define TMP_STR_LEN   64

static void aarch64_impl_str(char *str, int maxlen, int implementer)
{
	switch (implementer) {
	case 0x41:
		snprintf(str, maxlen, "ARM Limited");
		return;
	case 0x42:
		snprintf(str, maxlen, "Broadcom Corporation");
		return;
	case 0x43:
		snprintf(str, maxlen, "Marvell (Cavium) Inc.");
		return;
	case 0x44:
		snprintf(str, maxlen, "Digital Equipment Corporation");
		return;
	case 0x46:
		snprintf(str, maxlen, "Fujitsu Ltd.");
		return;
	case 0x49:
		snprintf(str, maxlen, "Infineon Technologies AG");
		return;
	case 0x4d:
		snprintf(str, maxlen, "Freescale Semiconductor Inc.");
		return;
	case 0x4e:
		snprintf(str, maxlen, "NVIDIA Corporation");
		return;
	case 0x50:
		snprintf(str, maxlen, "Applied Micro Circuits Corporation");
		return;
	case 0x51:
		snprintf(str, maxlen, "Qualcomm Inc.");
		return;
	case 0x56:
		snprintf(str, maxlen, "Marvell International Ltd.");
		return;
	case 0x69:
		snprintf(str, maxlen, "Intel Corporation");
		return;
	case 0xc0:
		snprintf(str, maxlen, "Ampere Computing");
		return;
	default:
		break;
	}

	snprintf(str, maxlen, "UNKNOWN (0x%x)", implementer);
}

static void aarch64_part_info(char *str, int maxlen, odp_cpu_arch_arm_t *cpu_isa, int implementer,
			      int part, int variant, int revision)
{
	*cpu_isa = ODP_CPU_ARCH_ARM_UNKNOWN;

	if (implementer == 0x41) {
		/* Part numbers are specified in Main ID Register (MIDR_EL1) documentation */
		switch (part) {
		case 0xd02:
			snprintf(str, maxlen, "Cortex-A34");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_0;
			return;
		case 0xd04:
			snprintf(str, maxlen, "Cortex-A35");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_0;
			return;
		case 0xd03:
			snprintf(str, maxlen, "Cortex-A53");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_0;
			return;
		case 0xd05:
			snprintf(str, maxlen, "Cortex-A55");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		case 0xd07:
			snprintf(str, maxlen, "Cortex-A57");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_0;
			return;
		case 0xd06:
			snprintf(str, maxlen, "Cortex-A65");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		case 0xd08:
			snprintf(str, maxlen, "Cortex-A72");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_0;
			return;
		case 0xd09:
			snprintf(str, maxlen, "Cortex-A73");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_0;
			return;
		case 0xd0a:
			snprintf(str, maxlen, "Cortex-A75");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		case 0xd0b:
			snprintf(str, maxlen, "Cortex-A76");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		case 0xd0c:
			snprintf(str, maxlen, "Neoverse N1");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		case 0xd0e:
			snprintf(str, maxlen, "Cortex-A76AE");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		case 0xd0d:
			snprintf(str, maxlen, "Cortex-A77");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		case 0xd40:
			snprintf(str, maxlen, "Neoverse V1");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_4;
			return;
		case 0xd41:
			snprintf(str, maxlen, "Cortex-A78");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		case 0xd42:
			snprintf(str, maxlen, "Cortex-A78AE");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		case 0xd44:
			snprintf(str, maxlen, "Cortex-X1");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		case 0xd46:
			snprintf(str, maxlen, "Cortex-A510");
			*cpu_isa = ODP_CPU_ARCH_ARMV9_0;
			return;
		case 0xd47:
			snprintf(str, maxlen, "Cortex-A710");
			*cpu_isa = ODP_CPU_ARCH_ARMV9_0;
			return;
		case 0xd48:
			snprintf(str, maxlen, "Cortex-X2");
			*cpu_isa = ODP_CPU_ARCH_ARMV9_0;
			return;
		case 0xd49:
			snprintf(str, maxlen, "Neoverse N2");
			*cpu_isa = ODP_CPU_ARCH_ARMV9_0;
			return;
		case 0xd4a:
			snprintf(str, maxlen, "Neoverse E1");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		case 0xd4b:
			snprintf(str, maxlen, "Cortex-A78C");
			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		case 0xd4d:
			snprintf(str, maxlen, "Cortex-A715");
			*cpu_isa = ODP_CPU_ARCH_ARMV9_0;
			return;
		case 0xd80:
			snprintf(str, maxlen, "Cortex-A520");
			*cpu_isa = ODP_CPU_ARCH_ARMV9_2;
			return;
		case 0xd81:
			snprintf(str, maxlen, "Cortex-A720");
			*cpu_isa = ODP_CPU_ARCH_ARMV9_2;
			return;
		default:
			break;
		}
	} else if (implementer == 0x43) {
		switch (part) {
		case 0xa1:
			snprintf(str, maxlen, "CN88XX, Pass %i.%i", variant + 1, revision);
			*cpu_isa = ODP_CPU_ARCH_ARMV8_1;
			return;
		case 0xa2:
			snprintf(str, maxlen, "CN81XX, Pass %i.%i", variant + 1, revision);
			*cpu_isa = ODP_CPU_ARCH_ARMV8_1;
			return;
		case 0xa3:
			snprintf(str, maxlen, "CN83XX, Pass %i.%i", variant + 1, revision);
			*cpu_isa = ODP_CPU_ARCH_ARMV8_1;
			return;
		case 0xaf:
			snprintf(str, maxlen, "CN99XX, Rev %c%i", 'A' + variant, revision);
			*cpu_isa = ODP_CPU_ARCH_ARMV8_1;
			return;
		case 0xb1:
			snprintf(str, maxlen, "CN98XX, Rev %c%i", 'A' + variant, revision);
			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		case 0xb2:
			/* Handle B0 errata: variant and revision numbers show up as A1 */
			if (variant == 0 && revision == 1)
				snprintf(str, maxlen, "CN96XX, Rev B0");
			else
				snprintf(str, maxlen, "CN96XX, Rev %c%i", 'A' + variant, revision);

			*cpu_isa = ODP_CPU_ARCH_ARMV8_2;
			return;
		default:
			break;
		}
	}

	snprintf(str, maxlen, "part 0x%x, var 0x%x, rev 0x%x",
		 part, variant, revision);
}

static odp_cpu_arch_arm_t arm_isa_version(void)
{
#if defined(__ARM_ARCH)
	if (__ARM_ARCH == 8) {
	#ifdef __ARM_FEATURE_QRDMX
		/* v8.1 or higher */
		return ODP_CPU_ARCH_ARMV8_1;
	#else
		return ODP_CPU_ARCH_ARMV8_0;
	#endif
	}

	if (__ARM_ARCH == 9) {
		/* v9.0 or higher */
		return ODP_CPU_ARCH_ARMV9_0;
	}

	if (__ARM_ARCH >= 800) {
		/* ACLE 2018 defines that from v8.1 onwards the value includes
		 * the minor version number: __ARM_ARCH = X * 100 + Y
		 * E.g. for Armv8.1 __ARM_ARCH = 801 */
		int major = __ARM_ARCH / 100;
		int minor = __ARM_ARCH - (major * 100);

		if (major == 8) {
			switch (minor) {
			case 0:
				return ODP_CPU_ARCH_ARMV8_0;
			case 1:
				return ODP_CPU_ARCH_ARMV8_1;
			case 2:
				return ODP_CPU_ARCH_ARMV8_2;
			case 3:
				return ODP_CPU_ARCH_ARMV8_3;
			case 4:
				return ODP_CPU_ARCH_ARMV8_4;
			case 5:
				return ODP_CPU_ARCH_ARMV8_5;
			case 6:
				return ODP_CPU_ARCH_ARMV8_6;
			case 7:
				return ODP_CPU_ARCH_ARMV8_7;
			case 8:
				return ODP_CPU_ARCH_ARMV8_8;
			case 9:
				return ODP_CPU_ARCH_ARMV8_9;
			default:
				return ODP_CPU_ARCH_ARM_UNKNOWN;
			}
		} else if (major == 9) {
			switch (minor) {
			case 0:
				return ODP_CPU_ARCH_ARMV9_0;
			case 1:
				return ODP_CPU_ARCH_ARMV9_1;
			case 2:
				return ODP_CPU_ARCH_ARMV9_2;
			case 3:
				return ODP_CPU_ARCH_ARMV9_3;
			default:
				return ODP_CPU_ARCH_ARM_UNKNOWN;
			}
		}
	}
#endif
	return ODP_CPU_ARCH_ARM_UNKNOWN;
}

int _odp_cpuinfo_parser(FILE *file, system_info_t *sysinfo)
{
	char str[1024];
	char impl_str[TMP_STR_LEN];
	char part_str[TMP_STR_LEN];
	const char *cur;
	long int impl, arch, var, part, rev;
	int id;

	sysinfo->cpu_arch = ODP_CPU_ARCH_ARM;
	sysinfo->cpu_isa_sw.arm = arm_isa_version();
	/* Linux cpuinfo does not have detailed ISA version number (CPU architecture: 8) */
	sysinfo->cpu_isa_hw.arm = ODP_CPU_ARCH_ARM_UNKNOWN;

	strcpy(sysinfo->cpu_arch_str, "aarch64");

	memset(impl_str, 0, sizeof(impl_str));
	memset(part_str, 0, sizeof(part_str));

	impl = 0;
	arch = 0;
	var  = 0;
	part = 0;
	rev  = 0;
	id   = 0;

	while (fgets(str, sizeof(str), file) != NULL && id < CONFIG_NUM_CPU_IDS) {
		/* Parse line by line a block of cpuinfo */
		cur = strstr(str, "CPU implementer");

		if (cur) {
			cur      = strchr(cur, ':');
			impl     = strtol(cur + 1, NULL, 16);
			aarch64_impl_str(impl_str, TMP_STR_LEN, impl);
			continue;
		}

		cur = strstr(str, "CPU architecture");

		if (cur) {
			cur  = strchr(cur, ':');
			arch = strtol(cur + 1, NULL, 10);
			continue;
		}

		cur = strstr(str, "CPU variant");

		if (cur) {
			cur  = strchr(cur, ':');
			var  = strtol(cur + 1, NULL, 16);
			continue;
		}

		cur = strstr(str, "CPU part");

		if (cur) {
			cur      = strchr(cur, ':');
			part     = strtol(cur + 1, NULL, 16);
			continue;
		}

		cur = strstr(str, "CPU revision");

		if (cur) {
			odp_cpu_arch_arm_t cpu_isa;

			cur = strchr(cur, ':');
			rev = strtol(cur + 1, NULL, 10);

			aarch64_part_info(part_str, TMP_STR_LEN, &cpu_isa, impl, part, var, rev);
			sysinfo->cpu_isa_hw.arm = cpu_isa;

			/* This is the last line about this cpu, update
			 * model string. */
			snprintf(sysinfo->model_str[id],
				 sizeof(sysinfo->model_str[id]),
				 "%s, %s, arch %li",
				 impl_str, part_str, arch);

			/* Some CPUs do not support cpufreq, use a dummy
			 * max freq. */
			if (sysinfo->cpu_hz_max[id] == 0) {
				uint64_t hz = sysinfo->default_cpu_hz_max;

				_ODP_WARN("CPU[%i] uses default max frequency of %" PRIu64 " "
					  "Hz from config file\n", id, hz);
				sysinfo->cpu_hz_max[id] = hz;
			}

			id++;
		}
	}

	return 0;
}

void _odp_sys_info_print_arch(void)
{
	_odp_cpu_flags_print_all();
}

uint64_t odp_cpu_arch_hz_current(int id ODP_UNUSED)
{
	return odp_global_ro.system_info.default_cpu_hz;
}
