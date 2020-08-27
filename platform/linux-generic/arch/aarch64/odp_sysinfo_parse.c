/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <odp/api/hints.h>
#include <odp_global_data.h>
#include <odp_sysinfo_internal.h>
#include <odp_debug_internal.h>

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
	default:
		break;
	}

	snprintf(str, maxlen, "UNKNOWN (0x%x)", implementer);
}

static void aarch64_part_str(char *str, int maxlen, int implementer,
			     int part, int variant, int revision)
{
	if (implementer == 0x41) {
		switch (part) {
		case 0xd02:
			snprintf(str, maxlen, "Cortex-A34");
			return;
		case 0xd04:
			snprintf(str, maxlen, "Cortex-A35");
			return;
		case 0xd03:
			snprintf(str, maxlen, "Cortex-A53");
			return;
		case 0xd05:
			snprintf(str, maxlen, "Cortex-A55");
			return;
		case 0xd07:
			snprintf(str, maxlen, "Cortex-A57");
			return;
		case 0xd06:
			snprintf(str, maxlen, "Cortex-A65");
			return;
		case 0xd08:
			snprintf(str, maxlen, "Cortex-A72");
			return;
		case 0xd09:
			snprintf(str, maxlen, "Cortex-A73");
			return;
		case 0xd0a:
			snprintf(str, maxlen, "Cortex-A75");
			return;
		case 0xd0b:
			snprintf(str, maxlen, "Cortex-A76");
			return;
		case 0xd0e:
			snprintf(str, maxlen, "Cortex-A76AE");
			return;
		case 0xd0d:
			snprintf(str, maxlen, "Cortex-A77");
			return;
		case 0xd41:
			snprintf(str, maxlen, "Cortex-A78");
			return;
		default:
			break;
		}
	} else if (implementer == 0x43) {
		switch (part) {
		case 0xa1:
			snprintf(str, maxlen, "CN88XX, Pass %i.%i",
				 variant + 1, revision);
			return;
		case 0xa2:
			snprintf(str, maxlen, "CN81XX, Pass %i.%i",
				 variant + 1, revision);
			return;
		case 0xa3:
			snprintf(str, maxlen, "CN83XX, Pass %i.%i",
				 variant + 1, revision);
			return;
		case 0xaf:
			snprintf(str, maxlen, "CN99XX, Rev %c%i", 'A' + variant, revision);
			return;
		case 0xb1:
			snprintf(str, maxlen, "CN98XX, Rev %c%i", 'A' + variant, revision);
			return;
		case 0xb2:
			/* Handle B0 errata: variant and revision numbers show up as A1 */
			if (variant == 0 && revision == 1)
				snprintf(str, maxlen, "CN96XX, Rev B0");
			else
				snprintf(str, maxlen, "CN96XX, Rev %c%i", 'A' + variant, revision);
			return;
		default:
			break;
		}
	}

	snprintf(str, maxlen, "part 0x%x, var 0x%x, rev 0x%x",
		 part, variant, revision);
}

int cpuinfo_parser(FILE *file, system_info_t *sysinfo)
{
	char str[1024];
	char impl_str[TMP_STR_LEN];
	char part_str[TMP_STR_LEN];
	const char *cur;
	long int impl, arch, var, part, rev;
	int id;

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
			cur = strchr(cur, ':');
			rev = strtol(cur + 1, NULL, 10);

			aarch64_part_str(part_str, TMP_STR_LEN,
					 impl, part, var, rev);

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

				ODP_PRINT("WARN: cpu[%i] uses default max "
					  "frequency of %" PRIu64 " Hz from "
					  "config file\n", id, hz);
				sysinfo->cpu_hz_max[id] = hz;
			}

			id++;
		}
	}

	return 0;
}

void sys_info_print_arch(void)
{
	const char *ndef = "n/a";

	/* Avoid compiler warning about unused variable */
	(void)ndef;

	/* See ARM C Language Extensions documentation for details */
	ODP_PRINT("ARM FEATURES:\n");

	ODP_PRINT("  __ARM_ARCH              ");
#ifdef __ARM_ARCH
	ODP_PRINT("%i\n", __ARM_ARCH);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_ARCH_ISA_A64      ");
#ifdef __ARM_ARCH_ISA_A64
	ODP_PRINT("%i\n", __ARM_ARCH_ISA_A64);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_NEON              ");
#ifdef __ARM_NEON
	ODP_PRINT("%i\n", __ARM_NEON);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_ATOMICS   ");
#ifdef __ARM_FEATURE_ATOMICS
	ODP_PRINT("%i\n", __ARM_FEATURE_ATOMICS);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_UNALIGNED ");
#ifdef __ARM_FEATURE_UNALIGNED
	ODP_PRINT("%i\n", __ARM_FEATURE_UNALIGNED);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_IDIV      ");
#ifdef __ARM_FEATURE_IDIV
	ODP_PRINT("%i\n", __ARM_FEATURE_IDIV);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_QRDMX     ");
#ifdef __ARM_FEATURE_QRDMX
	ODP_PRINT("%i\n", __ARM_FEATURE_QRDMX);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_DOTPROD   ");
#ifdef __ARM_FEATURE_DOTPROD
	ODP_PRINT("%i\n", __ARM_FEATURE_DOTPROD);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_CRYPTO    ");
#ifdef __ARM_FEATURE_CRYPTO
	ODP_PRINT("%i\n", __ARM_FEATURE_CRYPTO);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_SHA512    ");
#ifdef __ARM_FEATURE_SHA512
	ODP_PRINT("%i\n", __ARM_FEATURE_SHA512);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_SHA3      ");
#ifdef __ARM_FEATURE_SHA3
	ODP_PRINT("%i\n", __ARM_FEATURE_SHA3);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_SM3       ");
#ifdef __ARM_FEATURE_SM3
	ODP_PRINT("%i\n", __ARM_FEATURE_SM3);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_SM4       ");
#ifdef __ARM_FEATURE_SM4
	ODP_PRINT("%i\n", __ARM_FEATURE_SM4);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_CRC32     ");
#ifdef __ARM_FEATURE_CRC32
	ODP_PRINT("%i\n", __ARM_FEATURE_CRC32);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  ARM ISA version:        ");
#if defined(__ARM_ARCH)
	if (__ARM_ARCH < 8) {
		ODP_PRINT("v%i\n", __ARM_ARCH);
	} else if (__ARM_ARCH == 8) {
		/* Actually, this checks for new NEON instructions in
		 * v8.1, but is currently the only way to distinguish
		 * v8.0 and >=v8.1. */
	#ifdef __ARM_FEATURE_QRDMX
		ODP_PRINT("v8.1 or higher\n");
	#else
		ODP_PRINT("v8.0\n");
	#endif
	} else {
		/* ACLE 2018 defines that from v8.1 onwards the value includes
		 * the minor version number: __ARM_ARCH = X * 100 + Y
		 * E.g. for Armv8.1 __ARM_ARCH = 801 */
		int major = __ARM_ARCH / 100;
		int minor = __ARM_ARCH - (major * 100);

		ODP_PRINT("v%i.%i\n", major, minor);
	}
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("\n");
}

uint64_t odp_cpu_arch_hz_current(int id ODP_UNUSED)
{
	return odp_global_ro.system_info.default_cpu_hz;
}
