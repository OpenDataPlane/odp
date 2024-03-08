/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2020-2023 Nokia
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
	const char *name;
	const uint64_t bit_mask;
} hwcap_feat_flag_t;

/* Linux HWCAP and HWCAP2 flags
 *
 * See https://docs.kernel.org/arch/arm64/elf_hwcaps.html for meaning of each flag.
 */
static hwcap_feat_flag_t hwcap_flags[] = {
	{
		/* Floating-point support for single-precision and double-precision types */
		.name = "FEAT_FP",
#ifdef HWCAP_FP
		.bit_mask = HWCAP_FP,
#endif
	},

	{
		/* Advanced SIMD support for:
		 *  - integer byte, halfword, word and doubleword element operations
		 *  - single-precision and double-precision floating-point arithmetic */
		.name = "ASIMD",
#ifdef HWCAP_ASIMD
		.bit_mask = HWCAP_ASIMD,
#endif
	},

	{
		/* Generic Timer is configured to generate events at approx. 10KHz */
		.name = "EVTSTRM",
#ifdef HWCAP_EVTSTRM
		.bit_mask = HWCAP_EVTSTRM,
#endif
	},

	{
		/* Advanced SIMD AES Instructions */
		.name = "FEAT_AES",
#ifdef HWCAP_AES
		.bit_mask = HWCAP_AES,
#endif
	},

	{
		/* Advanced SIMD PMULL Instructions */
		.name = "FEAT_PMULL",
#ifdef HWCAP_PMULL
		.bit_mask = HWCAP_PMULL,
#endif
	},

	{
		/* Advanced SIMD SHA1 Instructions */
		.name = "FEAT_SHA1",
#ifdef HWCAP_SHA1
		.bit_mask = HWCAP_SHA1,
#endif
	},

	{
		/* Advanced SIMD SHA256 Instructions */
		.name = "FEAT_SHA256",
#ifdef HWCAP_SHA2
		.bit_mask = HWCAP_SHA2,
#endif
	},

	{
		/* CRC32 Instructions */
		.name = "FEAT_CRC32",
#ifdef HWCAP_CRC32
		.bit_mask = HWCAP_CRC32,
#endif
	},

	{
		/* Large System Extensions */
		.name = "FEAT_LSE",
#ifdef HWCAP_ATOMICS
		.bit_mask = HWCAP_ATOMICS,
#endif
	},

	{
		/* Half-precision Floating-point Data Processing Instructions */
		.name = "FEAT_FP16",
#ifdef HWCAP_FPHP
		.bit_mask = HWCAP_FPHP,
#endif
	},

	{
		/* Advanced SIMD support with half-precision floating-point arithmetic */
		.name = "ASIMDHP",
#ifdef HWCAP_ASIMDHP
		.bit_mask = HWCAP_ASIMDHP,
#endif
	},

	{
		/* Availability of EL0 Access to certain ID Registers */
		.name = "CPUID",
#ifdef HWCAP_CPUID
		.bit_mask = HWCAP_CPUID,
#endif
	},

	{
		/* Rounding Double Multiply Accumulate Extensions */
		.name = "FEAT_RDM",
#ifdef HWCAP_ASIMDRDM
		.bit_mask = HWCAP_ASIMDRDM,
#endif
	},

	{
		/* JavaScript FJCVTS Conversion Instructions */
		.name = "FEAT_JSCVT",
#ifdef HWCAP_JSCVT
		.bit_mask = HWCAP_JSCVT,
#endif
	},

	{
		/* Floating-point FCMLA and FCADD Instructions */
		.name = "FEAT_FCMA",
#ifdef HWCAP_FCMA
		.bit_mask = HWCAP_FCMA,
#endif
	},

	{
		/* Load-acquire RCpc Instructions */
		.name = "FEAT_LRCPC",
#ifdef HWCAP_LRCPC
		.bit_mask = HWCAP_LRCPC,
#endif
	},

	{
		/* DC CVAP Instructions */
		.name = "FEAT_DPB",
#ifdef HWCAP_DCPOP
		.bit_mask = HWCAP_DCPOP,
#endif
	},

	{
		/* Advanced SIMD EOR3, RAX1, XAR, and BCAX Instructions */
		.name = "FEAT_SHA3",
#ifdef HWCAP_SHA3
		.bit_mask = HWCAP_SHA3,
#endif
	},

	{
		/* Advanced SIMD SM3 Instructions */
		.name = "FEAT_SM3",
#ifdef HWCAP_SM3
		.bit_mask = HWCAP_SM3,
#endif
	},

	{
		/* Advanced SIMD SM4 Instructions */
		.name = "FEAT_SM4",
#ifdef HWCAP_SM4
		.bit_mask = HWCAP_SM4,
#endif
	},

	{
		/* Advanced SIMD Int8 Dot Product Instructions */
		.name = "FEAT_DotProd",
#ifdef HWCAP_ASIMDDP
		.bit_mask = HWCAP_ASIMDDP,
#endif
	},

	{
		/* Advanced SIMD SHA512 Instructions */
		.name = "FEAT_SHA512",
#ifdef HWCAP_SHA512
		.bit_mask = HWCAP_SHA512,
#endif
	},

	{
		/* Scalable Vector Extensions */
		.name = "FEAT_SVE",
#ifdef HWCAP_SVE
		.bit_mask = HWCAP_SVE,
#endif
	},

	{
		/* Half-precision Floating-point FMLAL Instructions */
		.name = "FEAT_FHM",
#ifdef HWCAP_ASIMDFHM
		.bit_mask = HWCAP_ASIMDFHM,
#endif
	},

	{
		/* Data Independent Timing Instructions */
		.name = "FEAT_DIT",
#ifdef HWCAP_DIT
		.bit_mask = HWCAP_DIT,
#endif
	},

	{
		/* Large System Extensions Version 2 */
		.name = "FEAT_LSE2",
#ifdef HWCAP_USCAT
		.bit_mask = HWCAP_USCAT,
#endif
	},

	{
		/* Load-acquire RCpc Instructions Version 2 */
		.name = "FEAT_LRCPC2",
#ifdef HWCAP_ILRCPC
		.bit_mask = HWCAP_ILRCPC,
#endif
	},

	{
		/* Condition Flag Manipulation Extensions */
		.name = "FEAT_FlagM",
#ifdef HWCAP_FLAGM
		.bit_mask = HWCAP_FLAGM,
#endif
	},

	{
		/* Speculative Store Bypass Safe Instructions */
		.name = "FEAT_SSBS2",
#ifdef HWCAP_SSBS
		.bit_mask = HWCAP_SSBS,
#endif
	},

	{
		/* Speculation Barrier Instructions */
		.name = "FEAT_SB",
#ifdef HWCAP_SB
		.bit_mask = HWCAP_SB,
#endif
	},

	{
		/* Pointer Authentication Extensions */
		.name = "FEAT_PAuth",
#ifdef HWCAP_PACA
		.bit_mask = HWCAP_PACA,
#endif
	},

	{
		/* Generic Authentication Extensions */
		.name = "PACG",
#ifdef HWCAP_PACG
		.bit_mask = HWCAP_PACG,
#endif
	}
};

static hwcap_feat_flag_t hwcap2_flags[] = {
	{
		/* DC CVADP instructions */
		.name = "FEAT_DPB2",
#ifdef HWCAP2_DCPODP
		.bit_mask = HWCAP2_DCPODP,
#endif
	},

	{
		/* Scalable Vector Extensions Version 2 */
		.name = "FEAT_SVE2",
#ifdef HWCAP2_SVE2
		.bit_mask = HWCAP2_SVE2,
#endif
	},

	{
		/* SVE AES Instructions */
		.name = "FEAT_SVE_AES",
#ifdef HWCAP2_SVEAES
		.bit_mask = HWCAP2_SVEAES,
#endif
	},

	{
		/* SVE PMULL Instructions */
		.name = "FEAT_SVE_PMULL128",
#ifdef HWCAP2_SVEPMULL
		.bit_mask = HWCAP2_SVEPMULL,
#endif
	},

	{
		/* SVE Bit Permute Instructions */
		.name = "FEAT_SVE_BitPerm",
#ifdef HWCAP2_SVEBITPERM
		.bit_mask = HWCAP2_SVEBITPERM,
#endif
	},

	{
		/* SVE SHA-3 Instructions */
		.name = "FEAT_SVE_SHA3",
#ifdef HWCAP2_SVESHA3
		.bit_mask = HWCAP2_SVESHA3,
#endif
	},

	{
		/* SVE SM4 Instructions */
		.name = "FEAT_SVE_SM4",
#ifdef HWCAP2_SVESM4
		.bit_mask = HWCAP2_SVESM4,
#endif
	},

	{
		/* Condition Flag Manipulation Extensions Version 2 */
		.name = "FEAT_FlagM2",
#ifdef HWCAP2_FLAGM2
		.bit_mask = HWCAP2_FLAGM2,
#endif
	},

	{
		/* FRINT32Z, FRINT32X, FRINT64Z, and FRINT64X instructions */
		.name = "FEAT_FRINTTS",
#ifdef HWCAP2_FRINT
		.bit_mask = HWCAP2_FRINT,
#endif
	},

	{
		/* SVE Int8 Matrix Multiplication Instructions */
		.name = "SVEI8MM",
#ifdef HWCAP2_SVEI8MM
		.bit_mask = HWCAP2_SVEI8MM,
#endif
	},

	{
		/* SVE Single-precision Floating-point Matrix Multiply Instructions */
		.name = "FEAT_F32MM",
#ifdef HWCAP2_SVEF32MM
		.bit_mask = HWCAP2_SVEF32MM,
#endif
	},

	{
		/* SVE Double-precision Floating-point Matrix Multiply Instructions */
		.name = "FEAT_F64MM",
#ifdef HWCAP2_SVEF64MM
		.bit_mask = HWCAP2_SVEF64MM,
#endif
	},

	{
		/* SVE BFloat16 Instructions */
		.name = "SVEBF16",
#ifdef HWCAP2_SVEBF16
		.bit_mask = HWCAP2_SVEBF16,
#endif
	},

	{
		/* Advanced SIMD and Floating-point Int8 Matrix Multiplication Instructions */
		.name = "FEAT_I8MM",
#ifdef HWCAP2_I8MM
		.bit_mask = HWCAP2_I8MM,
#endif
	},

	{
		/* Advanced SIMD and Floating-point BFloat16 Instructions */
		.name = "FEAT_BF16",
#ifdef HWCAP2_BF16
		.bit_mask = HWCAP2_BF16,
#endif
	},

	{
		/* Data Gathering Hint Extensions */
		.name = "FEAT_DGH",
#ifdef HWCAP2_DGH
		.bit_mask = HWCAP2_DGH,
#endif
	},

	{
		/* Random Number Generation Extensions */
		.name = "FEAT_RNG",
#ifdef HWCAP2_RNG
		.bit_mask = HWCAP2_RNG,
#endif
	},

	{
		/* Branch Target Identification Extensions */
		.name = "FEAT_BTI",
#ifdef HWCAP2_BTI
		.bit_mask = HWCAP2_BTI,
#endif
	},

	{
		/* Full Memory Tagging Extensions */
		.name = "FEAT_MTE2",
#ifdef HWCAP2_MTE
		.bit_mask = HWCAP2_MTE,
#endif
	},

	{
		.name = "ECV",
#ifdef HWCAP2_ECV
		.bit_mask = HWCAP2_ECV,
#endif
	},

	{
		.name = "AFP",
#ifdef HWCAP2_AFP
		.bit_mask = HWCAP2_AFP,
#endif
	},

	{
		.name = "RPRES",
#ifdef HWCAP2_RPRES
		.bit_mask = HWCAP2_RPRES,
#endif
	},

	{
		.name = "MTE3",
#ifdef HWCAP2_MTE3
		.bit_mask = HWCAP2_MTE3,
#endif
	},

	{
		.name = "SME",
#ifdef HWCAP2_SME
		.bit_mask = HWCAP2_SME,
#endif
	},

	{
		.name = "SME_I16I64",
#ifdef HWCAP2_SME_I16I64
		.bit_mask = HWCAP2_SME_I16I64,
#endif
	},

	{
		.name = "SME_F64F64",
#ifdef HWCAP2_SME_F64F64
		.bit_mask = HWCAP2_SME_F64F64,
#endif
	},

	{
		.name = "SME_I8I32",
#ifdef HWCAP2_SME_I8I32
		.bit_mask = HWCAP2_SME_I8I32,
#endif
	},

	{
		.name = "SME_F16F32",
#ifdef HWCAP2_SME_F16F32
		.bit_mask = HWCAP2_SME_F16F32,
#endif
	},

	{
		.name = "SME_B16F32",
#ifdef HWCAP2_SME_B16F32
		.bit_mask = HWCAP2_SME_B16F32,
#endif
	},

	{
		.name = "SME_F32F32",
#ifdef HWCAP2_SME_F32F32
		.bit_mask = HWCAP2_SME_F32F32,
#endif
	},

	{
		.name = "SME_FA64",
#ifdef HWCAP2_SME_FA64
		.bit_mask = HWCAP2_SME_FA64,
#endif
	},

	{
		.name = "WFXT",
#ifdef HWCAP2_WFXT
		.bit_mask = HWCAP2_WFXT,
#endif
	},

	{
		.name = "EBF16",
#ifdef HWCAP2_EBF16
		.bit_mask = HWCAP2_EBF16,
#endif
	},

	{
		.name = "SVE_EBF16",
#ifdef HWCAP2_SVE_EBF16
		.bit_mask = HWCAP2_SVE_EBF16,
#endif
	},

	{
		.name = "CSSC",
#ifdef HWCAP2_CSSC
		.bit_mask = HWCAP2_CSSC,
#endif
	},

	{
		.name = "RPRFM",
#ifdef HWCAP2_RPRFM
		.bit_mask = HWCAP2_RPRFM,
#endif
	},

	{
		.name = "SVE2P1",
#ifdef HWCAP2_SVE2P1
		.bit_mask = HWCAP2_SVE2P1,
#endif
	},

	{
		.name = "SME2",
#ifdef HWCAP2_SME2
		.bit_mask = HWCAP2_SME2,
#endif
	},

	{
		.name = "SME2P1",
#ifdef HWCAP2_SME2P1
		.bit_mask = HWCAP2_SME2P1,
#endif
	},

	{
		.name = "SME_I16I32",
#ifdef HWCAP2_SME_I16I32
		.bit_mask = HWCAP2_SME_I16I32,
#endif
	},

	{
		.name = "SME_BI32I32",
#ifdef HWCAP2_SME_BI32I32
		.bit_mask = HWCAP2_SME_BI32I32,
#endif
	},

	{
		.name = "SME_B16B16",
#ifdef HWCAP2_SME_B16B16
		.bit_mask = HWCAP2_SME_B16B16,
#endif
	},

	{
		.name = "SME_F16F16",
#ifdef HWCAP2_SME_F16F16
		.bit_mask = HWCAP2_SME_F16F16,
#endif
	},

	{
		.name = "MOPS",
#ifdef HWCAP2_MOPS
		.bit_mask = HWCAP2_MOPS,
#endif
	},
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
		if (hwcap & hwcap_flags[i].bit_mask)
			_ODP_PRINT("%s ", hwcap_flags[i].name);

	/* Supported HWCAP2 flags */
	for (i = 0; i < size2; i++)
		if (hwcap2 & hwcap2_flags[i].bit_mask)
			_ODP_PRINT("%s ", hwcap2_flags[i].name);

	_ODP_PRINT("\n\nARM FEATURES NOT SUPPORTED BY HARDWARE:\n");

	/* Unsupported HWCAP flags */
	for (i = 0; i < size; i++)
		if (hwcap_flags[i].bit_mask && (hwcap & hwcap_flags[i].bit_mask) == 0)
			_ODP_PRINT("%s ", hwcap_flags[i].name);

	/* Unsupported HWCAP2 flags */
	for (i = 0; i < size2; i++)
		if (hwcap2_flags[i].bit_mask && (hwcap2 & hwcap2_flags[i].bit_mask) == 0)
			_ODP_PRINT("%s ", hwcap2_flags[i].name);

	_ODP_PRINT("\n\nARM FEATURES UNKNOWN TO LINUX VERSION:\n");
	/* Unknown HWCAP flags */
	for (i = 0; i < size; i++)
		if (hwcap_flags[i].bit_mask == 0)
			_ODP_PRINT("%s ", hwcap_flags[i].name);

	/* Unknown HWCAP2 flags */
	for (i = 0; i < size2; i++)
		if (hwcap2_flags[i].bit_mask == 0)
			_ODP_PRINT("%s ", hwcap2_flags[i].name);

	_ODP_PRINT("\n\n");
}

void _odp_cpu_flags_print_all(void)
{
	_odp_sys_info_print_acle_flags();
	_odp_sys_info_print_hwcap_flags();
}
