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

	ODP_PRINT("  __ARM_ALIGN_MAX_PWR              ");
#ifdef __ARM_ALIGN_MAX_PWR
	ODP_PRINT("%i\n", __ARM_ALIGN_MAX_PWR);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_ALIGN_MAX_STACK_PWR        ");
#ifdef __ARM_ALIGN_MAX_STACK_PWR
	ODP_PRINT("%i\n", __ARM_ALIGN_MAX_STACK_PWR);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_ARCH                       ");
#ifdef __ARM_ARCH
	ODP_PRINT("%i\n", __ARM_ARCH);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_ARCH_ISA_A64               ");
#ifdef __ARM_ARCH_ISA_A64
	ODP_PRINT("%i\n", __ARM_ARCH_ISA_A64);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_BIG_ENDIAN                 ");
#ifdef __ARM_BIG_ENDIAN
	ODP_PRINT("%i\n", __ARM_BIG_ENDIAN);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_BF16_FORMAT_ALTERNATIVE    ");
#ifdef __ARM_BF16_FORMAT_ALTERNATIVE
	ODP_PRINT("%i\n", __ARM_BF16_FORMAT_ALTERNATIVE);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_ATOMICS            ");
#ifdef __ARM_FEATURE_ATOMICS
	ODP_PRINT("%i\n", __ARM_FEATURE_ATOMICS);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_BF16               ");
#ifdef __ARM_FEATURE_BF16
	ODP_PRINT("%i\n", __ARM_FEATURE_BF16);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_BTI_DEFAULT        ");
#ifdef __ARM_FEATURE_BTI_DEFAULT
	ODP_PRINT("%i\n", __ARM_FEATURE_BTI_DEFAULT);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_CDE                ");
#ifdef __ARM_FEATURE_CDE
	ODP_PRINT("%i\n", __ARM_FEATURE_CDE);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_CDE_COPROC         ");
#ifdef __ARM_FEATURE_CDE_COPROC
	ODP_PRINT("0x%X\n", __ARM_FEATURE_CDE_COPROC);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_CLZ                ");
#ifdef __ARM_FEATURE_CLZ
	ODP_PRINT("%i\n", __ARM_FEATURE_CLZ);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_COMPLEX            ");
#ifdef __ARM_FEATURE_COMPLEX
	ODP_PRINT("%i\n", __ARM_FEATURE_COMPLEX);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_COPROC             ");
#ifdef __ARM_FEATURE_COPROC
	ODP_PRINT("0x%X\n", __ARM_FEATURE_COPROC);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_CRC32              ");
#ifdef __ARM_FEATURE_CRC32
	ODP_PRINT("%i\n", __ARM_FEATURE_CRC32);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_CRYPTO             ");
#ifdef __ARM_FEATURE_CRYPTO
	ODP_PRINT("%i\n", __ARM_FEATURE_CRYPTO);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_DIRECTED_ROUNDING  ");
#ifdef __ARM_FEATURE_DIRECTED_ROUNDING
	ODP_PRINT("%i\n", __ARM_FEATURE_DIRECTED_ROUNDING);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_DOTPROD            ");
#ifdef __ARM_FEATURE_DOTPROD
	ODP_PRINT("%i\n", __ARM_FEATURE_DOTPROD);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_FMA                ");
#ifdef __ARM_FEATURE_FMA
	ODP_PRINT("%i\n", __ARM_FEATURE_FMA);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_FP16_FML           ");
#ifdef __ARM_FEATURE_FP16_FML
	ODP_PRINT("%i\n", __ARM_FEATURE_FP16_FML);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_FRINT              ");
#ifdef __ARM_FEATURE_FRINT
	ODP_PRINT("%i\n", __ARM_FEATURE_FRINT);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_IDIV               ");
#ifdef __ARM_FEATURE_IDIV
	ODP_PRINT("%i\n", __ARM_FEATURE_IDIV);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_JCVT               ");
#ifdef __ARM_FEATURE_JCVT
	ODP_PRINT("%i\n", __ARM_FEATURE_JCVT);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_MATMUL_INT8        ");
#ifdef __ARM_FEATURE_MATMUL_INT8
	ODP_PRINT("%i\n", __ARM_FEATURE_MATMUL_INT8);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_MEMORY_TAGGING     ");
#ifdef __ARM_FEATURE_MEMORY_TAGGING
	ODP_PRINT("%i\n", __ARM_FEATURE_MEMORY_TAGGING);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_MVE                ");
#ifdef __ARM_FEATURE_MVE
	ODP_PRINT("0x%X\n", __ARM_FEATURE_MVE);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_NUMERIC_MAXMIN     ");
#ifdef __ARM_FEATURE_NUMERIC_MAXMIN
	ODP_PRINT("%i\n", __ARM_FEATURE_NUMERIC_MAXMIN);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_PAC_DEFAULT        ");
#ifdef __ARM_FEATURE_PAC_DEFAULT
	ODP_PRINT("0x%X\n", __ARM_FEATURE_PAC_DEFAULT);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_QRDMX              ");
#ifdef __ARM_FEATURE_QRDMX
	ODP_PRINT("%i\n", __ARM_FEATURE_QRDMX);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_RNG                ");
#ifdef __ARM_FEATURE_RNG
	ODP_PRINT("%i\n", __ARM_FEATURE_RNG);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_SHA3               ");
#ifdef __ARM_FEATURE_SHA3
	ODP_PRINT("%i\n", __ARM_FEATURE_SHA3);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_SHA512             ");
#ifdef __ARM_FEATURE_SHA512
	ODP_PRINT("%i\n", __ARM_FEATURE_SHA512);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_SM3                ");
#ifdef __ARM_FEATURE_SM3
	ODP_PRINT("%i\n", __ARM_FEATURE_SM3);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_SM4                ");
#ifdef __ARM_FEATURE_SM4
	ODP_PRINT("%i\n", __ARM_FEATURE_SM4);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_TME                ");
#ifdef __ARM_FEATURE_TME
	ODP_PRINT("%i\n", __ARM_FEATURE_TME);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FEATURE_UNALIGNED          ");
#ifdef __ARM_FEATURE_UNALIGNED
	ODP_PRINT("%i\n", __ARM_FEATURE_UNALIGNED);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FP                         ");
#ifdef __ARM_FP
	ODP_PRINT("0x%X\n", __ARM_FP);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FP_FAST                    ");
#ifdef __ARM_FP_FAST
	ODP_PRINT("%i\n", __ARM_FP_FAST);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FP_FENV_ROUNDING           ");
#ifdef __ARM_FP_FENV_ROUNDING
	ODP_PRINT("%i\n", __ARM_FP_FENV_ROUNDING);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FP16_ARGS                  ");
#ifdef __ARM_FP16_ARGS
	ODP_PRINT("%i\n", __ARM_FP16_ARGS);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FP16_FORMAT_ALTERNATIVE    ");
#ifdef __ARM_FP16_FORMAT_ALTERNATIVE
	ODP_PRINT("%i\n", __ARM_FP16_FORMAT_ALTERNATIVE);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_FP16_FORMAT_IEEE           ");
#ifdef __ARM_FP16_FORMAT_IEEE
	ODP_PRINT("%i\n", __ARM_FP16_FORMAT_IEEE);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_NEON                       ");
#ifdef __ARM_NEON
	ODP_PRINT("%i\n", __ARM_NEON);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_NEON_FP                    ");
#ifdef __ARM_NEON_FP
	ODP_PRINT("0x%X\n", __ARM_NEON_FP);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_PCS_AAPCS64                ");
#ifdef __ARM_PCS_AAPCS64
	ODP_PRINT("%i\n", __ARM_PCS_AAPCS64);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_ROPI                       ");
#ifdef __ARM_ROPI
	ODP_PRINT("%i\n", __ARM_ROPI);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_RWPI                       ");
#ifdef __ARM_RWPI
	ODP_PRINT("%i\n", __ARM_RWPI);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_SIZEOF_MINIMAL_ENUM        ");
#ifdef __ARM_SIZEOF_MINIMAL_ENUM
	ODP_PRINT("%i\n", __ARM_SIZEOF_MINIMAL_ENUM);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  __ARM_SIZEOF_WCHAR_T             ");
#ifdef __ARM_SIZEOF_WCHAR_T
	ODP_PRINT("%i\n", __ARM_SIZEOF_WCHAR_T);
#else
	ODP_PRINT("%s\n", ndef);
#endif

	ODP_PRINT("  ARM ISA version:                 ");
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
