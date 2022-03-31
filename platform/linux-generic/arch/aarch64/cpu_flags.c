/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2020-2022, Nokia
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
	bool valid;
} hwcap_feat_flag_t;

static hwcap_feat_flag_t hwcap_flags[] = {
	{
		/* Floating-point Extensions */
		.feat_flag = "FEAT_FP",
#ifdef HWCAP_FP
		.hwcap_field = HWCAP_FP,
		.valid = 1,
#endif
	},

	{
		/* Floating-point Extensions */
		.feat_flag = "FEAT_FP",
#ifdef HWCAP_ASIMD
		.hwcap_field = HWCAP_ASIMD,
		.valid = 1,
#endif
	},

	{
		/* Generic Timer is configured to generate events at approx. 10KHz */
		.feat_flag = "HWCAP_EVTSTRM",
#ifdef HWCAP_EVTSTRM
		.hwcap_field = HWCAP_EVTSTRM,
		.valid = 1,
#endif
	},

	{
		/* Advanced SIMD AES Instructions */
		.feat_flag = "FEAT_AES",
#ifdef HWCAP_AES
		.hwcap_field = HWCAP_AES,
		.valid = 1,
#endif
	},

	{
		/* Advanced SIMD PMULL Instructions */
		.feat_flag = "FEAT_PMULL",
#ifdef HWCAP_PMULL
		.hwcap_field = HWCAP_PMULL,
		.valid = 1,
#endif
	},

	{
		/* Advanced SIMD SHA1 Instructions */
		.feat_flag = "FEAT_SHA1",
#ifdef HWCAP_SHA1
		.hwcap_field = HWCAP_SHA1,
		.valid = 1,
#endif
	},

	{
		/* Advanced SIMD SHA256 Instructions */
		.feat_flag = "FEAT_SHA256",
#ifdef HWCAP_SHA2
		.hwcap_field = HWCAP_SHA2,
		.valid = 1,
#endif
	},

	{
		/* CRC32 Instructions */
		.feat_flag = "FEAT_CRC32",
#ifdef HWCAP_CRC32
		.hwcap_field = HWCAP_CRC32,
		.valid = 1,
#endif
	},

	{
		/* Large System Extensions */
		.feat_flag = "FEAT_LSE",
#ifdef HWCAP_ATOMICS
		.hwcap_field = HWCAP_ATOMICS,
		.valid = 1,
#endif
	},

	{
		/* Half-precision Floating-point Data Processing Instructions */
		.feat_flag = "FEAT_FP16",
#ifdef HWCAP_FPHP
		.hwcap_field = HWCAP_FPHP,
		.valid = 1,
#endif
	},

	{
		/* Half-precision Floating-point Data Processing Instructions */
		.feat_flag = "FEAT_FP16",
#ifdef HWCAP_ASIMDHP
		.hwcap_field = HWCAP_ASIMDHP,
		.valid = 1,
#endif
	},

	{
		/* Availability of EL0 Access to certain ID Registers */
		.feat_flag = "HWCAP_CPUID",
#ifdef HWCAP_CPUID
		.hwcap_field = HWCAP_CPUID,
		.valid = 1,
#endif
	},

	{
		/* Rounding Double Multiply Accumulate Extensions */
		.feat_flag = "FEAT_RDM",
#ifdef HWCAP_ASIMDRDM
		.hwcap_field = HWCAP_ASIMDRDM,
		.valid = 1,
#endif
	},

	{
		/* JavaScript FJCVTS Conversion Instructions */
		.feat_flag = "FEAT_JSCVT",
#ifdef HWCAP_JSCVT
		.hwcap_field = HWCAP_JSCVT,
		.valid = 1,
#endif
	},

	{
		/* Floating-point FCMLA and FCADD Instructions */
		.feat_flag = "FEAT_FCMA",
#ifdef HWCAP_FCMA
		.hwcap_field = HWCAP_FCMA,
		.valid = 1,
#endif
	},

	{
		/* Load-acquire RCpc Instructions */
		.feat_flag = "FEAT_LRCPC",
#ifdef HWCAP_LRCPC
		.hwcap_field = HWCAP_LRCPC,
		.valid = 1,
#endif
	},

	{
		/* DC CVAP Instructions */
		.feat_flag = "FEAT_DPB",
#ifdef HWCAP_DCPOP
		.hwcap_field = HWCAP_DCPOP,
		.valid = 1,
#endif
	},

	{
		/* Advanced SIMD EOR3, RAX1, XAR, and BCAX Instructions */
		.feat_flag = "FEAT_SHA3",
#ifdef HWCAP_SHA3
		.hwcap_field = HWCAP_SHA3,
		.valid = 1,
#endif
	},

	{
		/* Advanced SIMD SM3 Instructions */
		.feat_flag = "FEAT_SM3",
#ifdef HWCAP_SM3
		.hwcap_field = HWCAP_SM3,
		.valid = 1,
#endif
	},

	{
		/* Advanced SIMD SM4 Instructions */
		.feat_flag = "FEAT_SM4",
#ifdef HWCAP_SM4
		.hwcap_field = HWCAP_SM4,
		.valid = 1,
#endif
	},

	{
		/* Advanced SIMD Int8 Dot Product Instructions */
		.feat_flag = "FEAT_DotProd",
#ifdef HWCAP_ASIMDDP
		.hwcap_field = HWCAP_ASIMDDP,
		.valid = 1,
#endif
	},

	{
		/* Advanced SIMD SHA512 Instructions */
		.feat_flag = "FEAT_SHA512",
#ifdef HWCAP_SHA512
		.hwcap_field = HWCAP_SHA512,
		.valid = 1,
#endif
	},

	{
		/* Scalable Vector Extensions */
		.feat_flag = "FEAT_SVE",
#ifdef HWCAP_SVE
		.hwcap_field = HWCAP_SVE,
		.valid = 1,
#endif
	},

	{
		/* Half-precision Floating-point FMLAL Instructions */
		.feat_flag = "FEAT_FHM",
#ifdef HWCAP_ASIMDFHM
		.hwcap_field = HWCAP_ASIMDFHM,
		.valid = 1,
#endif
	},

	{
		/* Data Independent Timing Instructions */
		.feat_flag = "FEAT_DIT",
#ifdef HWCAP_DIT
		.hwcap_field = HWCAP_DIT,
		.valid = 1,
#endif
	},

	{
		/* Large System Extensions Version 2 */
		.feat_flag = "FEAT_LSE2",
#ifdef HWCAP_USCAT
		.hwcap_field = HWCAP_USCAT,
		.valid = 1,
#endif
	},

	{
		/* Load-acquire RCpc Instructions Version 2 */
		.feat_flag = "FEAT_LRCPC2",
#ifdef HWCAP_ILRCPC
		.hwcap_field = HWCAP_ILRCPC,
		.valid = 1,
#endif
	},

	{
		/* Condition Flag Manipulation Extensions */
		.feat_flag = "FEAT_FlagM",
#ifdef HWCAP_FLAGM
		.hwcap_field = HWCAP_FLAGM,
		.valid = 1,
#endif
	},

	{
		/* Speculative Store Bypass Safe Instructions */
		.feat_flag = "FEAT_SSBS2",
#ifdef HWCAP_SSBS
		.hwcap_field = HWCAP_SSBS,
		.valid = 1,
#endif
	},

	{
		/* Speculation Barrier Instructions */
		.feat_flag = "FEAT_SB",
#ifdef HWCAP_SB
		.hwcap_field = HWCAP_SB,
		.valid = 1,
#endif
	},

	{
		/* Pointer Authentication Extensions */
		.feat_flag = "FEAT_PAuth",
#ifdef HWCAP_PACA
		.hwcap_field = HWCAP_PACA,
		.valid = 1,
#endif
	},

	{
		/* Generic Authentication Extensions */
		.feat_flag = "HWCAP_PACG",
#ifdef HWCAP_PACG
		.hwcap_field = HWCAP_PACG,
		.valid = 1,
#endif
	}
};

static hwcap_feat_flag_t hwcap2_flags[] = {
	{
		/* DC CVADP instructions */
		.feat_flag = "FEAT_DPB2",
#ifdef HWCAP2_DCPODP
		.hwcap_field = HWCAP2_DCPODP,
		.valid = 1,
#endif
	},

	{
		/* Scalable Vector Extensions Version 2 */
		.feat_flag = "FEAT_SVE2",
#ifdef HWCAP2_SVE2
		.hwcap_field = HWCAP2_SVE2,
		.valid = 1,
#endif
	},

	{
		/* SVE AES Instructions */
		.feat_flag = "FEAT_SVE_AES",
#ifdef HWCAP2_SVEAES
		.hwcap_field = HWCAP2_SVEAES,
		.valid = 1,
#endif
	},

	{
		/* SVE PMULL Instructions */
		.feat_flag = "FEAT_SVE_PMULL128",
#ifdef HWCAP2_SVEPMULL
		.hwcap_field = HWCAP2_SVEPMULL,
		.valid = 1,
#endif
	},

	{
		/* SVE Bit Permute Instructions */
		.feat_flag = "FEAT_SVE_BitPerm",
#ifdef HWCAP2_SVEBITPERM
		.hwcap_field = HWCAP2_SVEBITPERM,
		.valid = 1,
#endif
	},

	{
		/* SVE SHA-3 Instructions */
		.feat_flag = "FEAT_SVE_SHA3",
#ifdef HWCAP2_SVESHA3
		.hwcap_field = HWCAP2_SVESHA3,
		.valid = 1,
#endif
	},

	{
		/* SVE SM4 Instructions */
		.feat_flag = "FEAT_SVE_SM4",
#ifdef HWCAP2_SVESM4
		.hwcap_field = HWCAP2_SVESM4,
		.valid = 1,
#endif
	},

	{
		/* Condition Flag Manipulation Extensions Version 2 */
		.feat_flag = "FEAT_FlagM2",
#ifdef HWCAP2_FLAGM2
		.hwcap_field = HWCAP2_FLAGM2,
		.valid = 1,
#endif
	},

	{
		/* FRINT32Z, FRINT32X, FRINT64Z, and FRINT64X instructions */
		.feat_flag = "FEAT_FRINTTS",
#ifdef HWCAP2_FRINT
		.hwcap_field = HWCAP2_FRINT,
		.valid = 1,
#endif
	},

	{
		/* SVE Int8 Matrix Multiplication Instructions */
		.feat_flag = "FEAT_I8MM",
#ifdef HWCAP2_SVEI8MM
		.hwcap_field = HWCAP2_SVEI8MM,
		.valid = 1,
#endif
	},

	{
		/* SVE Single-precision Floating-point Matrix Multiply Instructions */
		.feat_flag = "FEAT_F32MM",
#ifdef HWCAP2_SVEF32MM
		.hwcap_field = HWCAP2_SVEF32MM,
		.valid = 1,
#endif
	},

	{
		/* SVE Double-precision Floating-point Matrix Multiply Instructions */
		.feat_flag = "FEAT_F64MM",
#ifdef HWCAP2_SVEF64MM
		.hwcap_field = HWCAP2_SVEF64MM,
		.valid = 1,
#endif
	},

	{
		/* SVE BFloat16 Instructions */
		.feat_flag = "FEAT_BF16",
#ifdef HWCAP2_SVEBF16
		.hwcap_field = HWCAP2_SVEBF16,
		.valid = 1,
#endif
	},

	{
		/* Advanced SIMD and Floating-point Int8 Matrix Multiplication Instructions */
		.feat_flag = "FEAT_I8MM",
#ifdef HWCAP2_I8MM
		.hwcap_field = HWCAP2_I8MM,
		.valid = 1,
#endif
	},

	{
		/* Advanced SIMD and Floating-point BFloat16 Instructions */
		.feat_flag = "FEAT_BF16",
#ifdef HWCAP2_BF16
		.hwcap_field = HWCAP2_BF16,
		.valid = 1,
#endif
	},

	{
		/* Data Gathering Hint Extensions */
		.feat_flag = "FEAT_DGH",
#ifdef HWCAP2_DGH
		.hwcap_field = HWCAP2_DGH,
		.valid = 1,
#endif
	},

	{
		/* Random Number Generation Extensions */
		.feat_flag = "FEAT_RNG",
#ifdef HWCAP2_RNG
		.hwcap_field = HWCAP2_RNG,
		.valid = 1,
#endif
	},

	{
		/* Branch Target Identification Extensions */
		.feat_flag = "FEAT_BTI",
#ifdef HWCAP2_BTI
		.hwcap_field = HWCAP2_BTI,
		.valid = 1,
#endif
	},

	{
		/* Full Memory Tagging Extensions */
		.feat_flag = "FEAT_MTE2",
#ifdef HWCAP2_MTE
		.hwcap_field = HWCAP2_MTE,
		.valid = 1,
#endif
	}
};

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

static int check_hwcap_duplicates(unsigned int hwcap_field)
{
	int ret = 0;

	/* FP and AdvSIMD fields of the AArch64 Processor
	 * Feature Register 0 must have the same value and are
	 * defined by the same feature flag. Print the flag
	 * only once. */
#ifdef HWCAP_ASIMD
		if (hwcap_field == HWCAP_ASIMD)
			ret = 1;
#endif
#ifdef HWCAP_ASIMDHP
		if (hwcap_field == HWCAP_ASIMDHP)
			ret = 1;
#endif

	return ret;
}

static void _odp_sys_info_print_hwcap_flags(void)
{
	unsigned long hwcaps, hwcaps2;
	unsigned int size, size2;

	ODP_PRINT("ARM FEATURES SUPPORTED BY HARDWARE:\n");

	/* Print supported hardware flags via AT_HWCAP entry of the hwcaps
	 * auxiliary vector. */
	hwcaps = getauxval(AT_HWCAP);
	size = _ODP_ARRAY_SIZE(hwcap_flags);
	for (unsigned int i = 0; i < size; i++) {
		if (hwcap_flags[i].valid) {
			if (check_hwcap_duplicates(hwcap_flags[i].hwcap_field)) {
				hwcaps = hwcaps >> 1;
				continue;
			}

			if (hwcaps & 0x01)
				ODP_PRINT("%s ", hwcap_flags[i].feat_flag);
			hwcaps = hwcaps >> 1;
		}
	}

	/* Print supported hardware flags via AT_HWCAP2 entry of the hwcaps
	 * auxiliary vector. */
	hwcaps2 = getauxval(AT_HWCAP2);
	size2 = _ODP_ARRAY_SIZE(hwcap2_flags);
	for (unsigned long i = 0; i < size2; i++) {
		if (hwcap2_flags[i].valid) {
			if (hwcaps2 & 0x01)
				ODP_PRINT("%s ", hwcap2_flags[i].feat_flag);
			hwcaps2 = hwcaps2 >> 1;
		}
	}

	ODP_PRINT("\n");

	/* Re-initialize hwcaps and hwcaps2 */
	hwcaps = 0;
	hwcaps2 = 0;

	ODP_PRINT("\nARM FEATURES NOT SUPPORTED BY HARDWARE:\n");

	hwcaps = getauxval(AT_HWCAP);
	for (unsigned long i = 0; i < size; i++) {
		if (hwcap_flags[i].valid) {
			if (check_hwcap_duplicates(hwcap_flags[i].hwcap_field)) {
				hwcaps = hwcaps >> 1;
				continue;
			}

			if (!(hwcaps & 0x01))
				ODP_PRINT("%s ", hwcap_flags[i].feat_flag);
			hwcaps = hwcaps >> 1;
		}
	}

	hwcaps2 = getauxval(AT_HWCAP2);
	for (unsigned long i = 0; i < size2; i++) {
		if (hwcap2_flags[i].valid) {
			if (!(hwcaps2 & 0x01))
				ODP_PRINT("%s ", hwcap2_flags[i].feat_flag);
			hwcaps2 = hwcaps2 >> 1;
		}
	}

	ODP_PRINT("\n");

	ODP_PRINT("\nARM FEATURES NOT SUPPORTED BY KERNEL:\n");

	for (unsigned long i = 0; i < size; i++) {
		if (!hwcap_flags[i].valid)
			ODP_PRINT("%s ", hwcap_flags[i].feat_flag);
	}

	for (unsigned long i = 0; i < size2; i++) {
		if (!hwcap2_flags[i].valid)
			ODP_PRINT("%s ", hwcap2_flags[i].feat_flag);
	}

	ODP_PRINT("\n\n");
}

void _odp_cpu_flags_print_all(void)
{
	_odp_sys_info_print_acle_flags();
	_odp_sys_info_print_hwcap_flags();
}
