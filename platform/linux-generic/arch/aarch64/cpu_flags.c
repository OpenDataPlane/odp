/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2020-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/hints.h>

#include <odp_debug_internal.h>
#include <odp_macros_internal.h>

#include "cpu_flags.h"

#include <asm/hwcap.h>
#include <string.h>
#include <stdlib.h>
#include <sys/auxv.h>

typedef struct {
	const char *feat_flag;
	const unsigned int hwcap_field;
} hwcap_feat_flag_t;

/* Linux HWCAP and HWCAP2 flags
 *
 * See https://docs.kernel.org/arch/arm64/elf_hwcaps.html for meaning of each flag.
 */
static hwcap_feat_flag_t hwcap_flags[] = {
	{
		/* Floating-point support for single-precision and double-precision types */
		.feat_flag = "FEAT_FP",
#ifdef HWCAP_FP
		.hwcap_field = HWCAP_FP,
#endif
	},

	{
		/* Advanced SIMD support for:
		 *  - integer byte, halfword, word and doubleword element operations
		 *  - single-precision and double-precision floating-point arithmetic */
		.feat_flag = "ASIMD",
#ifdef HWCAP_ASIMD
		.hwcap_field = HWCAP_ASIMD,
#endif
	},

	{
		/* Generic Timer is configured to generate events at approx. 10KHz */
		.feat_flag = "EVTSTRM",
#ifdef HWCAP_EVTSTRM
		.hwcap_field = HWCAP_EVTSTRM,
#endif
	},

	{
		/* Advanced SIMD AES Instructions */
		.feat_flag = "FEAT_AES",
#ifdef HWCAP_AES
		.hwcap_field = HWCAP_AES,
#endif
	},

	{
		/* Advanced SIMD PMULL Instructions */
		.feat_flag = "FEAT_PMULL",
#ifdef HWCAP_PMULL
		.hwcap_field = HWCAP_PMULL,
#endif
	},

	{
		/* Advanced SIMD SHA1 Instructions */
		.feat_flag = "FEAT_SHA1",
#ifdef HWCAP_SHA1
		.hwcap_field = HWCAP_SHA1,
#endif
	},

	{
		/* Advanced SIMD SHA256 Instructions */
		.feat_flag = "FEAT_SHA256",
#ifdef HWCAP_SHA2
		.hwcap_field = HWCAP_SHA2,
#endif
	},

	{
		/* CRC32 Instructions */
		.feat_flag = "FEAT_CRC32",
#ifdef HWCAP_CRC32
		.hwcap_field = HWCAP_CRC32,
#endif
	},

	{
		/* Large System Extensions */
		.feat_flag = "FEAT_LSE",
#ifdef HWCAP_ATOMICS
		.hwcap_field = HWCAP_ATOMICS,
#endif
	},

	{
		/* Half-precision Floating-point Data Processing Instructions */
		.feat_flag = "FEAT_FP16",
#ifdef HWCAP_FPHP
		.hwcap_field = HWCAP_FPHP,
#endif
	},

	{
		/* Advanced SIMD support with half-precision floating-point arithmetic */
		.feat_flag = "ASIMDHP",
#ifdef HWCAP_ASIMDHP
		.hwcap_field = HWCAP_ASIMDHP,
#endif
	},

	{
		/* Availability of EL0 Access to certain ID Registers */
		.feat_flag = "CPUID",
#ifdef HWCAP_CPUID
		.hwcap_field = HWCAP_CPUID,
#endif
	},

	{
		/* Rounding Double Multiply Accumulate Extensions */
		.feat_flag = "FEAT_RDM",
#ifdef HWCAP_ASIMDRDM
		.hwcap_field = HWCAP_ASIMDRDM,
#endif
	},

	{
		/* JavaScript FJCVTS Conversion Instructions */
		.feat_flag = "FEAT_JSCVT",
#ifdef HWCAP_JSCVT
		.hwcap_field = HWCAP_JSCVT,
#endif
	},

	{
		/* Floating-point FCMLA and FCADD Instructions */
		.feat_flag = "FEAT_FCMA",
#ifdef HWCAP_FCMA
		.hwcap_field = HWCAP_FCMA,
#endif
	},

	{
		/* Load-acquire RCpc Instructions */
		.feat_flag = "FEAT_LRCPC",
#ifdef HWCAP_LRCPC
		.hwcap_field = HWCAP_LRCPC,
#endif
	},

	{
		/* DC CVAP Instructions */
		.feat_flag = "FEAT_DPB",
#ifdef HWCAP_DCPOP
		.hwcap_field = HWCAP_DCPOP,
#endif
	},

	{
		/* Advanced SIMD EOR3, RAX1, XAR, and BCAX Instructions */
		.feat_flag = "FEAT_SHA3",
#ifdef HWCAP_SHA3
		.hwcap_field = HWCAP_SHA3,
#endif
	},

	{
		/* Advanced SIMD SM3 Instructions */
		.feat_flag = "FEAT_SM3",
#ifdef HWCAP_SM3
		.hwcap_field = HWCAP_SM3,
#endif
	},

	{
		/* Advanced SIMD SM4 Instructions */
		.feat_flag = "FEAT_SM4",
#ifdef HWCAP_SM4
		.hwcap_field = HWCAP_SM4,
#endif
	},

	{
		/* Advanced SIMD Int8 Dot Product Instructions */
		.feat_flag = "FEAT_DotProd",
#ifdef HWCAP_ASIMDDP
		.hwcap_field = HWCAP_ASIMDDP,
#endif
	},

	{
		/* Advanced SIMD SHA512 Instructions */
		.feat_flag = "FEAT_SHA512",
#ifdef HWCAP_SHA512
		.hwcap_field = HWCAP_SHA512,
#endif
	},

	{
		/* Scalable Vector Extensions */
		.feat_flag = "FEAT_SVE",
#ifdef HWCAP_SVE
		.hwcap_field = HWCAP_SVE,
#endif
	},

	{
		/* Half-precision Floating-point FMLAL Instructions */
		.feat_flag = "FEAT_FHM",
#ifdef HWCAP_ASIMDFHM
		.hwcap_field = HWCAP_ASIMDFHM,
#endif
	},

	{
		/* Data Independent Timing Instructions */
		.feat_flag = "FEAT_DIT",
#ifdef HWCAP_DIT
		.hwcap_field = HWCAP_DIT,
#endif
	},

	{
		/* Large System Extensions Version 2 */
		.feat_flag = "FEAT_LSE2",
#ifdef HWCAP_USCAT
		.hwcap_field = HWCAP_USCAT,
#endif
	},

	{
		/* Load-acquire RCpc Instructions Version 2 */
		.feat_flag = "FEAT_LRCPC2",
#ifdef HWCAP_ILRCPC
		.hwcap_field = HWCAP_ILRCPC,
#endif
	},

	{
		/* Condition Flag Manipulation Extensions */
		.feat_flag = "FEAT_FlagM",
#ifdef HWCAP_FLAGM
		.hwcap_field = HWCAP_FLAGM,
#endif
	},

	{
		/* Speculative Store Bypass Safe Instructions */
		.feat_flag = "FEAT_SSBS2",
#ifdef HWCAP_SSBS
		.hwcap_field = HWCAP_SSBS,
#endif
	},

	{
		/* Speculation Barrier Instructions */
		.feat_flag = "FEAT_SB",
#ifdef HWCAP_SB
		.hwcap_field = HWCAP_SB,
#endif
	},

	{
		/* Pointer Authentication Extensions */
		.feat_flag = "FEAT_PAuth",
#ifdef HWCAP_PACA
		.hwcap_field = HWCAP_PACA,
#endif
	},

	{
		/* Generic Authentication Extensions */
		.feat_flag = "PACG",
#ifdef HWCAP_PACG
		.hwcap_field = HWCAP_PACG,
#endif
	}
};

static hwcap_feat_flag_t hwcap2_flags[] = {
	{
		/* DC CVADP instructions */
		.feat_flag = "FEAT_DPB2",
#ifdef HWCAP2_DCPODP
		.hwcap_field = HWCAP2_DCPODP,
#endif
	},

	{
		/* Scalable Vector Extensions Version 2 */
		.feat_flag = "FEAT_SVE2",
#ifdef HWCAP2_SVE2
		.hwcap_field = HWCAP2_SVE2,
#endif
	},

	{
		/* SVE AES Instructions */
		.feat_flag = "FEAT_SVE_AES",
#ifdef HWCAP2_SVEAES
		.hwcap_field = HWCAP2_SVEAES,
#endif
	},

	{
		/* SVE PMULL Instructions */
		.feat_flag = "FEAT_SVE_PMULL128",
#ifdef HWCAP2_SVEPMULL
		.hwcap_field = HWCAP2_SVEPMULL,
#endif
	},

	{
		/* SVE Bit Permute Instructions */
		.feat_flag = "FEAT_SVE_BitPerm",
#ifdef HWCAP2_SVEBITPERM
		.hwcap_field = HWCAP2_SVEBITPERM,
#endif
	},

	{
		/* SVE SHA-3 Instructions */
		.feat_flag = "FEAT_SVE_SHA3",
#ifdef HWCAP2_SVESHA3
		.hwcap_field = HWCAP2_SVESHA3,
#endif
	},

	{
		/* SVE SM4 Instructions */
		.feat_flag = "FEAT_SVE_SM4",
#ifdef HWCAP2_SVESM4
		.hwcap_field = HWCAP2_SVESM4,
#endif
	},

	{
		/* Condition Flag Manipulation Extensions Version 2 */
		.feat_flag = "FEAT_FlagM2",
#ifdef HWCAP2_FLAGM2
		.hwcap_field = HWCAP2_FLAGM2,
#endif
	},

	{
		/* FRINT32Z, FRINT32X, FRINT64Z, and FRINT64X instructions */
		.feat_flag = "FEAT_FRINTTS",
#ifdef HWCAP2_FRINT
		.hwcap_field = HWCAP2_FRINT,
#endif
	},

	{
		/* SVE Int8 Matrix Multiplication Instructions */
		.feat_flag = "SVEI8MM",
#ifdef HWCAP2_SVEI8MM
		.hwcap_field = HWCAP2_SVEI8MM,
#endif
	},

	{
		/* SVE Single-precision Floating-point Matrix Multiply Instructions */
		.feat_flag = "FEAT_F32MM",
#ifdef HWCAP2_SVEF32MM
		.hwcap_field = HWCAP2_SVEF32MM,
#endif
	},

	{
		/* SVE Double-precision Floating-point Matrix Multiply Instructions */
		.feat_flag = "FEAT_F64MM",
#ifdef HWCAP2_SVEF64MM
		.hwcap_field = HWCAP2_SVEF64MM,
#endif
	},

	{
		/* SVE BFloat16 Instructions */
		.feat_flag = "SVEBF16",
#ifdef HWCAP2_SVEBF16
		.hwcap_field = HWCAP2_SVEBF16,
#endif
	},

	{
		/* Advanced SIMD and Floating-point Int8 Matrix Multiplication Instructions */
		.feat_flag = "FEAT_I8MM",
#ifdef HWCAP2_I8MM
		.hwcap_field = HWCAP2_I8MM,
#endif
	},

	{
		/* Advanced SIMD and Floating-point BFloat16 Instructions */
		.feat_flag = "FEAT_BF16",
#ifdef HWCAP2_BF16
		.hwcap_field = HWCAP2_BF16,
#endif
	},

	{
		/* Data Gathering Hint Extensions */
		.feat_flag = "FEAT_DGH",
#ifdef HWCAP2_DGH
		.hwcap_field = HWCAP2_DGH,
#endif
	},

	{
		/* Random Number Generation Extensions */
		.feat_flag = "FEAT_RNG",
#ifdef HWCAP2_RNG
		.hwcap_field = HWCAP2_RNG,
#endif
	},

	{
		/* Branch Target Identification Extensions */
		.feat_flag = "FEAT_BTI",
#ifdef HWCAP2_BTI
		.hwcap_field = HWCAP2_BTI,
#endif
	},

	{
		/* Full Memory Tagging Extensions */
		.feat_flag = "FEAT_MTE2",
#ifdef HWCAP2_MTE
		.hwcap_field = HWCAP2_MTE,
#endif
	}
};

static void _odp_sys_info_print_acle_flags(void)
{
	const char *ndef = "n/a";

	/* Avoid compiler warning about unused variable */
	(void)ndef;

	/* See ARM C Language Extensions documentation for details */
	_ODP_PRINT("ARM FEATURES:\n");

	_ODP_PRINT("  __ARM_ALIGN_MAX_PWR              ");
#ifdef __ARM_ALIGN_MAX_PWR
	_ODP_PRINT("%i\n", __ARM_ALIGN_MAX_PWR);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_ALIGN_MAX_STACK_PWR        ");
#ifdef __ARM_ALIGN_MAX_STACK_PWR
	_ODP_PRINT("%i\n", __ARM_ALIGN_MAX_STACK_PWR);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_ARCH                       ");
#ifdef __ARM_ARCH
	_ODP_PRINT("%i\n", __ARM_ARCH);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_ARCH_ISA_A64               ");
#ifdef __ARM_ARCH_ISA_A64
	_ODP_PRINT("%i\n", __ARM_ARCH_ISA_A64);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_BIG_ENDIAN                 ");
#ifdef __ARM_BIG_ENDIAN
	_ODP_PRINT("%i\n", __ARM_BIG_ENDIAN);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_BF16_FORMAT_ALTERNATIVE    ");
#ifdef __ARM_BF16_FORMAT_ALTERNATIVE
	_ODP_PRINT("%i\n", __ARM_BF16_FORMAT_ALTERNATIVE);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_ATOMICS            ");
#ifdef __ARM_FEATURE_ATOMICS
	_ODP_PRINT("%i\n", __ARM_FEATURE_ATOMICS);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_BF16               ");
#ifdef __ARM_FEATURE_BF16
	_ODP_PRINT("%i\n", __ARM_FEATURE_BF16);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_BTI_DEFAULT        ");
#ifdef __ARM_FEATURE_BTI_DEFAULT
	_ODP_PRINT("%i\n", __ARM_FEATURE_BTI_DEFAULT);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_CDE                ");
#ifdef __ARM_FEATURE_CDE
	_ODP_PRINT("%i\n", __ARM_FEATURE_CDE);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_CDE_COPROC         ");
#ifdef __ARM_FEATURE_CDE_COPROC
	_ODP_PRINT("0x%X\n", __ARM_FEATURE_CDE_COPROC);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_CLZ                ");
#ifdef __ARM_FEATURE_CLZ
	_ODP_PRINT("%i\n", __ARM_FEATURE_CLZ);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_COMPLEX            ");
#ifdef __ARM_FEATURE_COMPLEX
	_ODP_PRINT("%i\n", __ARM_FEATURE_COMPLEX);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_COPROC             ");
#ifdef __ARM_FEATURE_COPROC
	_ODP_PRINT("0x%X\n", __ARM_FEATURE_COPROC);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_CRC32              ");
#ifdef __ARM_FEATURE_CRC32
	_ODP_PRINT("%i\n", __ARM_FEATURE_CRC32);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_CRYPTO             ");
#ifdef __ARM_FEATURE_CRYPTO
	_ODP_PRINT("%i\n", __ARM_FEATURE_CRYPTO);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_DIRECTED_ROUNDING  ");
#ifdef __ARM_FEATURE_DIRECTED_ROUNDING
	_ODP_PRINT("%i\n", __ARM_FEATURE_DIRECTED_ROUNDING);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_DOTPROD            ");
#ifdef __ARM_FEATURE_DOTPROD
	_ODP_PRINT("%i\n", __ARM_FEATURE_DOTPROD);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_FMA                ");
#ifdef __ARM_FEATURE_FMA
	_ODP_PRINT("%i\n", __ARM_FEATURE_FMA);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_FP16_FML           ");
#ifdef __ARM_FEATURE_FP16_FML
	_ODP_PRINT("%i\n", __ARM_FEATURE_FP16_FML);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_FRINT              ");
#ifdef __ARM_FEATURE_FRINT
	_ODP_PRINT("%i\n", __ARM_FEATURE_FRINT);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_IDIV               ");
#ifdef __ARM_FEATURE_IDIV
	_ODP_PRINT("%i\n", __ARM_FEATURE_IDIV);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_JCVT               ");
#ifdef __ARM_FEATURE_JCVT
	_ODP_PRINT("%i\n", __ARM_FEATURE_JCVT);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_MATMUL_INT8        ");
#ifdef __ARM_FEATURE_MATMUL_INT8
	_ODP_PRINT("%i\n", __ARM_FEATURE_MATMUL_INT8);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_MEMORY_TAGGING     ");
#ifdef __ARM_FEATURE_MEMORY_TAGGING
	_ODP_PRINT("%i\n", __ARM_FEATURE_MEMORY_TAGGING);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_MVE                ");
#ifdef __ARM_FEATURE_MVE
	_ODP_PRINT("0x%X\n", __ARM_FEATURE_MVE);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_NUMERIC_MAXMIN     ");
#ifdef __ARM_FEATURE_NUMERIC_MAXMIN
	_ODP_PRINT("%i\n", __ARM_FEATURE_NUMERIC_MAXMIN);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_PAC_DEFAULT        ");
#ifdef __ARM_FEATURE_PAC_DEFAULT
	_ODP_PRINT("0x%X\n", __ARM_FEATURE_PAC_DEFAULT);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_QRDMX              ");
#ifdef __ARM_FEATURE_QRDMX
	_ODP_PRINT("%i\n", __ARM_FEATURE_QRDMX);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_RNG                ");
#ifdef __ARM_FEATURE_RNG
	_ODP_PRINT("%i\n", __ARM_FEATURE_RNG);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_SHA3               ");
#ifdef __ARM_FEATURE_SHA3
	_ODP_PRINT("%i\n", __ARM_FEATURE_SHA3);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_SHA512             ");
#ifdef __ARM_FEATURE_SHA512
	_ODP_PRINT("%i\n", __ARM_FEATURE_SHA512);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_SM3                ");
#ifdef __ARM_FEATURE_SM3
	_ODP_PRINT("%i\n", __ARM_FEATURE_SM3);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_SM4                ");
#ifdef __ARM_FEATURE_SM4
	_ODP_PRINT("%i\n", __ARM_FEATURE_SM4);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_TME                ");
#ifdef __ARM_FEATURE_TME
	_ODP_PRINT("%i\n", __ARM_FEATURE_TME);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FEATURE_UNALIGNED          ");
#ifdef __ARM_FEATURE_UNALIGNED
	_ODP_PRINT("%i\n", __ARM_FEATURE_UNALIGNED);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FP                         ");
#ifdef __ARM_FP
	_ODP_PRINT("0x%X\n", __ARM_FP);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FP_FAST                    ");
#ifdef __ARM_FP_FAST
	_ODP_PRINT("%i\n", __ARM_FP_FAST);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FP_FENV_ROUNDING           ");
#ifdef __ARM_FP_FENV_ROUNDING
	_ODP_PRINT("%i\n", __ARM_FP_FENV_ROUNDING);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FP16_ARGS                  ");
#ifdef __ARM_FP16_ARGS
	_ODP_PRINT("%i\n", __ARM_FP16_ARGS);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FP16_FORMAT_ALTERNATIVE    ");
#ifdef __ARM_FP16_FORMAT_ALTERNATIVE
	_ODP_PRINT("%i\n", __ARM_FP16_FORMAT_ALTERNATIVE);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_FP16_FORMAT_IEEE           ");
#ifdef __ARM_FP16_FORMAT_IEEE
	_ODP_PRINT("%i\n", __ARM_FP16_FORMAT_IEEE);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_NEON                       ");
#ifdef __ARM_NEON
	_ODP_PRINT("%i\n", __ARM_NEON);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_NEON_FP                    ");
#ifdef __ARM_NEON_FP
	_ODP_PRINT("0x%X\n", __ARM_NEON_FP);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_PCS_AAPCS64                ");
#ifdef __ARM_PCS_AAPCS64
	_ODP_PRINT("%i\n", __ARM_PCS_AAPCS64);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_ROPI                       ");
#ifdef __ARM_ROPI
	_ODP_PRINT("%i\n", __ARM_ROPI);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_RWPI                       ");
#ifdef __ARM_RWPI
	_ODP_PRINT("%i\n", __ARM_RWPI);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_SIZEOF_MINIMAL_ENUM        ");
#ifdef __ARM_SIZEOF_MINIMAL_ENUM
	_ODP_PRINT("%i\n", __ARM_SIZEOF_MINIMAL_ENUM);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  __ARM_SIZEOF_WCHAR_T             ");
#ifdef __ARM_SIZEOF_WCHAR_T
	_ODP_PRINT("%i\n", __ARM_SIZEOF_WCHAR_T);
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("  ARM ISA version:                 ");
#if defined(__ARM_ARCH)
	if (__ARM_ARCH < 8) {
		_ODP_PRINT("v%i\n", __ARM_ARCH);
	} else if (__ARM_ARCH == 8) {
		/* Actually, this checks for new NEON instructions in
		 * v8.1, but is currently the only way to distinguish
		 * v8.0 and >=v8.1. */
	#ifdef __ARM_FEATURE_QRDMX
		_ODP_PRINT("v8.1 or higher\n");
	#else
		_ODP_PRINT("v8.0\n");
	#endif
	} else {
		/* ACLE 2018 defines that from v8.1 onwards the value includes
		 * the minor version number: __ARM_ARCH = X * 100 + Y
		 * E.g. for Armv8.1 __ARM_ARCH = 801 */
		int major = __ARM_ARCH / 100;
		int minor = __ARM_ARCH - (major * 100);

		_ODP_PRINT("v%i.%i\n", major, minor);
	}
#else
	_ODP_PRINT("%s\n", ndef);
#endif

	_ODP_PRINT("\n");
}

static void _odp_sys_info_print_hwcap_flags(void)
{
	uint64_t hwcap, hwcap2;
	uint32_t size, size2, i;

	hwcap  = getauxval(AT_HWCAP);
	hwcap2 = getauxval(AT_HWCAP2);
	size   = _ODP_ARRAY_SIZE(hwcap_flags);
	size2  = _ODP_ARRAY_SIZE(hwcap2_flags);

	_ODP_PRINT("ARM FEATURES SUPPORTED BY HARDWARE:\n");

	/* Supported HWCAP flags */
	for (i = 0; i < size; i++)
		if (hwcap & hwcap_flags[i].hwcap_field)
			_ODP_PRINT("%s ", hwcap_flags[i].feat_flag);

	/* Supported HWCAP2 flags */
	for (i = 0; i < size2; i++)
		if (hwcap2 & hwcap2_flags[i].hwcap_field)
			_ODP_PRINT("%s ", hwcap2_flags[i].feat_flag);

	_ODP_PRINT("\n\nARM FEATURES NOT SUPPORTED BY HARDWARE:\n");

	/* Unsupported HWCAP flags */
	for (i = 0; i < size; i++)
		if (hwcap_flags[i].hwcap_field && (hwcap & hwcap_flags[i].hwcap_field) == 0)
			_ODP_PRINT("%s ", hwcap_flags[i].feat_flag);

	/* Unsupported HWCAP2 flags */
	for (i = 0; i < size2; i++)
		if (hwcap2_flags[i].hwcap_field && (hwcap2 & hwcap2_flags[i].hwcap_field) == 0)
			_ODP_PRINT("%s ", hwcap2_flags[i].feat_flag);

	_ODP_PRINT("\n\nARM FEATURES UNKNOWN TO LINUX VERSION:\n");
	/* Unknown HWCAP flags */
	for (i = 0; i < size; i++)
		if (hwcap_flags[i].hwcap_field == 0)
			_ODP_PRINT("%s ", hwcap_flags[i].feat_flag);

	/* Unknown HWCAP2 flags */
	for (i = 0; i < size2; i++)
		if (hwcap2_flags[i].hwcap_field == 0)
			_ODP_PRINT("%s ", hwcap2_flags[i].feat_flag);

	_ODP_PRINT("\n\n");
}

void _odp_cpu_flags_print_all(void)
{
	_odp_sys_info_print_acle_flags();
	_odp_sys_info_print_hwcap_flags();
}
