/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2020-2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string.h>
#include <stdlib.h>

#include <odp/api/hints.h>
#include <odp_debug_internal.h>
#include "cpu_flags.h"

static void _odp_sys_info_print_acle_flags(void)
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

	ODP_PRINT("  __ARM_FEATURE_ATOMICS   ");
#ifdef __ARM_FEATURE_ATOMICS
	ODP_PRINT("%i\n", __ARM_FEATURE_ATOMICS);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_CRC32     ");
#ifdef __ARM_FEATURE_CRC32
	ODP_PRINT("%i\n", __ARM_FEATURE_CRC32);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_CRYPTO    ");
#ifdef __ARM_FEATURE_CRYPTO
	ODP_PRINT("%i\n", __ARM_FEATURE_CRYPTO);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_DOTPROD   ");
#ifdef __ARM_FEATURE_DOTPROD
	ODP_PRINT("%i\n", __ARM_FEATURE_DOTPROD);
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

	ODP_PRINT("  __ARM_FEATURE_SHA3      ");
#ifdef __ARM_FEATURE_SHA3
	ODP_PRINT("%i\n", __ARM_FEATURE_SHA3);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_SHA512    ");
#ifdef __ARM_FEATURE_SHA512
	ODP_PRINT("%i\n", __ARM_FEATURE_SHA512);
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

	ODP_PRINT("  __ARM_FEATURE_UNALIGNED ");
#ifdef __ARM_FEATURE_UNALIGNED
	ODP_PRINT("%i\n", __ARM_FEATURE_UNALIGNED);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_NEON              ");
#ifdef __ARM_NEON
	ODP_PRINT("%i\n", __ARM_NEON);
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

void _odp_cpu_flags_print_all(void)
{
	_odp_sys_info_print_acle_flags();
}
