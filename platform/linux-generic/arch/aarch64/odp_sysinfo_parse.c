/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
		snprintf(str, maxlen, "Cavium Inc.");
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
		case 0xd03:
			snprintf(str, maxlen, "Cortex-A53");
			return;
		case 0xd05:
			snprintf(str, maxlen, "Cortex-A55");
			return;
		case 0xd07:
			snprintf(str, maxlen, "Cortex-A57");
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
			snprintf(str, maxlen, "CN99XX, Pass %i.%i",
				 variant + 1, revision);
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

	while (fgets(str, sizeof(str), file) != NULL && id < CONFIG_NUM_CPU) {
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
				uint64_t hz = DUMMY_MAX_MHZ * 1000000;

				ODP_PRINT("WARN: cpu[%i] uses dummy max frequency %u MHz\n",
					  id, DUMMY_MAX_MHZ);
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
	printf("ARM FEATURES:\n");

	printf("  __ARM_ARCH           ");
#ifdef __ARM_ARCH
	printf("%i\n", __ARM_ARCH);
#else
	printf("%s\n", ndef);
#endif

	printf("  __ARM_ARCH_ISA_A64   ");
#ifdef __ARM_ARCH_ISA_A64
	printf("%i\n", __ARM_ARCH_ISA_A64);
#else
	printf("%s\n", ndef);
#endif

#if defined(__ARM_ARCH) && __ARM_ARCH >= 8
	/* Actually, this checks for new NEON instructions in
	 * v8.1, but is currently the only way to distinguish
	 * v8.0 and >=v8.1. */
	printf("    ARMv8 ISA version  ");
#ifdef __ARM_FEATURE_QRDMX
	printf("v8.1 or higher\n");
#else
	printf("v8.0\n");
#endif
#endif

#ifdef __ARM_FEATURE_QRDMX
	/* Actually, this checks for new NEON instructions in
	 * v8.1, but is currently the only way to distinguish
	 * v8.0 and >=v8.1. */
	printf("    ARMv8.1 instructions\n");
#endif

	printf("  __ARM_NEON           ");
#ifdef __ARM_NEON
	printf("%i\n", __ARM_NEON);
#else
	printf("%s\n", ndef);
#endif

	printf("  __ARM_FEATURE_IDIV   ");
#ifdef __ARM_FEATURE_IDIV
	printf("%i\n", __ARM_FEATURE_IDIV);
#else
	printf("%s\n", ndef);
#endif

	printf("  __ARM_FEATURE_CRYPTO ");
#ifdef __ARM_FEATURE_CRYPTO
	printf("%i\n", __ARM_FEATURE_CRYPTO);
#else
	printf("%s\n", ndef);
#endif

	printf("  __ARM_FEATURE_CRC32  ");
#ifdef __ARM_FEATURE_CRC32
	printf("%i\n", __ARM_FEATURE_CRC32);
#else
	printf("%s\n", ndef);
#endif

	printf("\n");
}

uint64_t odp_cpu_arch_hz_current(int id)
{
	(void)id;

	return 0;
}
