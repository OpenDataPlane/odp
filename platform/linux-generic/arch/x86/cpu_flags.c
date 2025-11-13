/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2023 Nokia
 *
 * Copyright(c) 2010-2015 Intel Corporation
 *   - lib/eal/x86/include/rte_cpuflags.h
 *   - lib/eal/x86/rte_cpuflags.c
 *   - lib/eal/x86/rte_cpuid.h
 */

#include "cpu_flags.h"

#include <odp/api/abi/time_cpu.h>

#include <odp_debug_internal.h>
#include <odp_global_data.h>

#include <cpuid.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>

enum rte_cpu_flag_t {
	/* (EAX 01h) ECX features*/
	RTE_CPUFLAG_SSE3 = 0,               /**< SSE3 */
	RTE_CPUFLAG_PCLMULQDQ,              /**< PCLMULQDQ */
	RTE_CPUFLAG_DTES64,                 /**< DTES64 */
	RTE_CPUFLAG_MONITOR,                /**< MONITOR */
	RTE_CPUFLAG_DS_CPL,                 /**< DS_CPL */
	RTE_CPUFLAG_VMX,                    /**< VMX */
	RTE_CPUFLAG_SMX,                    /**< SMX */
	RTE_CPUFLAG_EIST,                   /**< EIST */
	RTE_CPUFLAG_TM2,                    /**< TM2 */
	RTE_CPUFLAG_SSSE3,                  /**< SSSE3 */
	RTE_CPUFLAG_CNXT_ID,                /**< CNXT_ID */
	RTE_CPUFLAG_FMA,                    /**< FMA */
	RTE_CPUFLAG_CMPXCHG16B,             /**< CMPXCHG16B */
	RTE_CPUFLAG_XTPR,                   /**< XTPR */
	RTE_CPUFLAG_PDCM,                   /**< PDCM */
	RTE_CPUFLAG_PCID,                   /**< PCID */
	RTE_CPUFLAG_DCA,                    /**< DCA */
	RTE_CPUFLAG_SSE4_1,                 /**< SSE4_1 */
	RTE_CPUFLAG_SSE4_2,                 /**< SSE4_2 */
	RTE_CPUFLAG_X2APIC,                 /**< X2APIC */
	RTE_CPUFLAG_MOVBE,                  /**< MOVBE */
	RTE_CPUFLAG_POPCNT,                 /**< POPCNT */
	RTE_CPUFLAG_TSC_DEADLINE,           /**< TSC_DEADLINE */
	RTE_CPUFLAG_AES,                    /**< AES */
	RTE_CPUFLAG_XSAVE,                  /**< XSAVE */
	RTE_CPUFLAG_OSXSAVE,                /**< OSXSAVE */
	RTE_CPUFLAG_AVX,                    /**< AVX */
	RTE_CPUFLAG_F16C,                   /**< F16C */
	RTE_CPUFLAG_RDRAND,                 /**< RDRAND */
	RTE_CPUFLAG_HYPERVISOR,             /**< Running in a VM */

	/* (EAX 01h) EDX features */
	RTE_CPUFLAG_FPU,                    /**< FPU */
	RTE_CPUFLAG_VME,                    /**< VME */
	RTE_CPUFLAG_DE,                     /**< DE */
	RTE_CPUFLAG_PSE,                    /**< PSE */
	RTE_CPUFLAG_TSC,                    /**< TSC */
	RTE_CPUFLAG_MSR,                    /**< MSR */
	RTE_CPUFLAG_PAE,                    /**< PAE */
	RTE_CPUFLAG_MCE,                    /**< MCE */
	RTE_CPUFLAG_CX8,                    /**< CX8 */
	RTE_CPUFLAG_APIC,                   /**< APIC */
	RTE_CPUFLAG_SEP,                    /**< SEP */
	RTE_CPUFLAG_MTRR,                   /**< MTRR */
	RTE_CPUFLAG_PGE,                    /**< PGE */
	RTE_CPUFLAG_MCA,                    /**< MCA */
	RTE_CPUFLAG_CMOV,                   /**< CMOV */
	RTE_CPUFLAG_PAT,                    /**< PAT */
	RTE_CPUFLAG_PSE36,                  /**< PSE36 */
	RTE_CPUFLAG_PSN,                    /**< PSN */
	RTE_CPUFLAG_CLFSH,                  /**< CLFSH */
	RTE_CPUFLAG_DS,                     /**< DS */
	RTE_CPUFLAG_ACPI,                   /**< ACPI */
	RTE_CPUFLAG_MMX,                    /**< MMX */
	RTE_CPUFLAG_FXSR,                   /**< FXSR */
	RTE_CPUFLAG_SSE,                    /**< SSE */
	RTE_CPUFLAG_SSE2,                   /**< SSE2 */
	RTE_CPUFLAG_SS,                     /**< SS */
	RTE_CPUFLAG_HTT,                    /**< HTT */
	RTE_CPUFLAG_TM,                     /**< TM */
	RTE_CPUFLAG_PBE,                    /**< PBE */

	/* (EAX 06h) EAX features */
	RTE_CPUFLAG_DIGTEMP,                /**< DIGTEMP */
	RTE_CPUFLAG_TRBOBST,                /**< TRBOBST */
	RTE_CPUFLAG_ARAT,                   /**< ARAT */
	RTE_CPUFLAG_PLN,                    /**< PLN */
	RTE_CPUFLAG_ECMD,                   /**< ECMD */
	RTE_CPUFLAG_PTM,                    /**< PTM */

	/* (EAX 06h) ECX features */
	RTE_CPUFLAG_MPERF_APERF_MSR,        /**< MPERF_APERF_MSR */
	RTE_CPUFLAG_ACNT2,                  /**< ACNT2 */
	RTE_CPUFLAG_ENERGY_EFF,             /**< ENERGY_EFF */

	/* (EAX 07h, ECX 0h) EBX features */
	RTE_CPUFLAG_FSGSBASE,               /**< FSGSBASE */
	RTE_CPUFLAG_BMI1,                   /**< BMI1 */
	RTE_CPUFLAG_HLE,                    /**< Hardware Lock elision */
	RTE_CPUFLAG_AVX2,                   /**< AVX2 */
	RTE_CPUFLAG_SMEP,                   /**< SMEP */
	RTE_CPUFLAG_BMI2,                   /**< BMI2 */
	RTE_CPUFLAG_ERMS,                   /**< ERMS */
	RTE_CPUFLAG_INVPCID,                /**< INVPCID */
	RTE_CPUFLAG_RTM,                    /**< Transactional memory */
	RTE_CPUFLAG_AVX512F,                /**< AVX512F */
	RTE_CPUFLAG_RDSEED,                 /**< RDSEED instruction */

	/* (EAX 80000001h) ECX features */
	RTE_CPUFLAG_LAHF_SAHF,              /**< LAHF_SAHF */
	RTE_CPUFLAG_LZCNT,                  /**< LZCNT */

	/* (EAX 80000001h) EDX features */
	RTE_CPUFLAG_SYSCALL,                /**< SYSCALL */
	RTE_CPUFLAG_XD,                     /**< XD */
	RTE_CPUFLAG_1GB_PG,                 /**< 1GB_PG */
	RTE_CPUFLAG_RDTSCP,                 /**< RDTSCP */
	RTE_CPUFLAG_EM64T,                  /**< EM64T */

	/* (EAX 80000007h) EDX features */
	RTE_CPUFLAG_INVTSC,                 /**< INVTSC */

	RTE_CPUFLAG_AVX512DQ,               /**< AVX512 Doubleword and Quadword */
	RTE_CPUFLAG_AVX512IFMA,             /**< AVX512 Integer Fused Multiply-Add */
	RTE_CPUFLAG_AVX512CD,               /**< AVX512 Conflict Detection*/
	RTE_CPUFLAG_AVX512BW,               /**< AVX512 Byte and Word */
	RTE_CPUFLAG_AVX512VL,               /**< AVX512 Vector Length */
	RTE_CPUFLAG_AVX512VBMI,             /**< AVX512 Vector Bit Manipulation */
	RTE_CPUFLAG_AVX512VBMI2,            /**< AVX512 Vector Bit Manipulation 2 */
	RTE_CPUFLAG_GFNI,                   /**< Galois Field New Instructions */
	RTE_CPUFLAG_VAES,                   /**< Vector AES */
	RTE_CPUFLAG_VPCLMULQDQ,             /**< Vector Carry-less Multiply */
	RTE_CPUFLAG_AVX512VNNI,
	/**< AVX512 Vector Neural Network Instructions */
	RTE_CPUFLAG_AVX512BITALG,           /**< AVX512 Bit Algorithms */
	RTE_CPUFLAG_AVX512VPOPCNTDQ,        /**< AVX512 Vector Popcount */
	RTE_CPUFLAG_CLDEMOTE,               /**< Cache Line Demote */
	RTE_CPUFLAG_MOVDIRI,                /**< Direct Store Instructions */
	RTE_CPUFLAG_MOVDIR64B,              /**< Direct Store Instructions 64B */
	RTE_CPUFLAG_AVX512VP2INTERSECT,     /**< AVX512 Two Register Intersection */

	RTE_CPUFLAG_WAITPKG,                /**< UMONITOR/UMWAIT/TPAUSE */

	/* The last item */
	RTE_CPUFLAG_NUMFLAGS,               /**< This should always be the last! */
};

enum cpu_register_t {
	RTE_REG_EAX = 0,
	RTE_REG_EBX,
	RTE_REG_ECX,
	RTE_REG_EDX,
};

typedef uint32_t cpuid_registers_t[4];

/**
 * Struct to hold a processor feature entry
 */
struct feature_entry {
	uint32_t leaf;				/**< cpuid leaf */
	uint32_t subleaf;			/**< cpuid subleaf */
	uint32_t reg;				/**< cpuid register */
	uint32_t bit;				/**< cpuid register bit */
#define CPU_FLAG_NAME_MAX_LEN 64
	char name[CPU_FLAG_NAME_MAX_LEN];       /**< String for printing */
};

#define FEAT_DEF(name, leaf, subleaf, reg, bit) \
	[RTE_CPUFLAG_##name] = {leaf, subleaf, reg, bit, #name },

static const struct feature_entry cpu_feature_table[] = {
	FEAT_DEF(SSE3, 0x00000001, 0, RTE_REG_ECX,  0)
	FEAT_DEF(PCLMULQDQ, 0x00000001, 0, RTE_REG_ECX,  1)
	FEAT_DEF(DTES64, 0x00000001, 0, RTE_REG_ECX,  2)
	FEAT_DEF(MONITOR, 0x00000001, 0, RTE_REG_ECX,  3)
	FEAT_DEF(DS_CPL, 0x00000001, 0, RTE_REG_ECX,  4)
	FEAT_DEF(VMX, 0x00000001, 0, RTE_REG_ECX,  5)
	FEAT_DEF(SMX, 0x00000001, 0, RTE_REG_ECX,  6)
	FEAT_DEF(EIST, 0x00000001, 0, RTE_REG_ECX,  7)
	FEAT_DEF(TM2, 0x00000001, 0, RTE_REG_ECX,  8)
	FEAT_DEF(SSSE3, 0x00000001, 0, RTE_REG_ECX,  9)
	FEAT_DEF(CNXT_ID, 0x00000001, 0, RTE_REG_ECX, 10)
	FEAT_DEF(FMA, 0x00000001, 0, RTE_REG_ECX, 12)
	FEAT_DEF(CMPXCHG16B, 0x00000001, 0, RTE_REG_ECX, 13)
	FEAT_DEF(XTPR, 0x00000001, 0, RTE_REG_ECX, 14)
	FEAT_DEF(PDCM, 0x00000001, 0, RTE_REG_ECX, 15)
	FEAT_DEF(PCID, 0x00000001, 0, RTE_REG_ECX, 17)
	FEAT_DEF(DCA, 0x00000001, 0, RTE_REG_ECX, 18)
	FEAT_DEF(SSE4_1, 0x00000001, 0, RTE_REG_ECX, 19)
	FEAT_DEF(SSE4_2, 0x00000001, 0, RTE_REG_ECX, 20)
	FEAT_DEF(X2APIC, 0x00000001, 0, RTE_REG_ECX, 21)
	FEAT_DEF(MOVBE, 0x00000001, 0, RTE_REG_ECX, 22)
	FEAT_DEF(POPCNT, 0x00000001, 0, RTE_REG_ECX, 23)
	FEAT_DEF(TSC_DEADLINE, 0x00000001, 0, RTE_REG_ECX, 24)
	FEAT_DEF(AES, 0x00000001, 0, RTE_REG_ECX, 25)
	FEAT_DEF(XSAVE, 0x00000001, 0, RTE_REG_ECX, 26)
	FEAT_DEF(OSXSAVE, 0x00000001, 0, RTE_REG_ECX, 27)
	FEAT_DEF(AVX, 0x00000001, 0, RTE_REG_ECX, 28)
	FEAT_DEF(F16C, 0x00000001, 0, RTE_REG_ECX, 29)
	FEAT_DEF(RDRAND, 0x00000001, 0, RTE_REG_ECX, 30)
	FEAT_DEF(HYPERVISOR, 0x00000001, 0, RTE_REG_ECX, 31)

	FEAT_DEF(FPU, 0x00000001, 0, RTE_REG_EDX,  0)
	FEAT_DEF(VME, 0x00000001, 0, RTE_REG_EDX,  1)
	FEAT_DEF(DE, 0x00000001, 0, RTE_REG_EDX,  2)
	FEAT_DEF(PSE, 0x00000001, 0, RTE_REG_EDX,  3)
	FEAT_DEF(TSC, 0x00000001, 0, RTE_REG_EDX,  4)
	FEAT_DEF(MSR, 0x00000001, 0, RTE_REG_EDX,  5)
	FEAT_DEF(PAE, 0x00000001, 0, RTE_REG_EDX,  6)
	FEAT_DEF(MCE, 0x00000001, 0, RTE_REG_EDX,  7)
	FEAT_DEF(CX8, 0x00000001, 0, RTE_REG_EDX,  8)
	FEAT_DEF(APIC, 0x00000001, 0, RTE_REG_EDX,  9)
	FEAT_DEF(SEP, 0x00000001, 0, RTE_REG_EDX, 11)
	FEAT_DEF(MTRR, 0x00000001, 0, RTE_REG_EDX, 12)
	FEAT_DEF(PGE, 0x00000001, 0, RTE_REG_EDX, 13)
	FEAT_DEF(MCA, 0x00000001, 0, RTE_REG_EDX, 14)
	FEAT_DEF(CMOV, 0x00000001, 0, RTE_REG_EDX, 15)
	FEAT_DEF(PAT, 0x00000001, 0, RTE_REG_EDX, 16)
	FEAT_DEF(PSE36, 0x00000001, 0, RTE_REG_EDX, 17)
	FEAT_DEF(PSN, 0x00000001, 0, RTE_REG_EDX, 18)
	FEAT_DEF(CLFSH, 0x00000001, 0, RTE_REG_EDX, 19)
	FEAT_DEF(DS, 0x00000001, 0, RTE_REG_EDX, 21)
	FEAT_DEF(ACPI, 0x00000001, 0, RTE_REG_EDX, 22)
	FEAT_DEF(MMX, 0x00000001, 0, RTE_REG_EDX, 23)
	FEAT_DEF(FXSR, 0x00000001, 0, RTE_REG_EDX, 24)
	FEAT_DEF(SSE, 0x00000001, 0, RTE_REG_EDX, 25)
	FEAT_DEF(SSE2, 0x00000001, 0, RTE_REG_EDX, 26)
	FEAT_DEF(SS, 0x00000001, 0, RTE_REG_EDX, 27)
	FEAT_DEF(HTT, 0x00000001, 0, RTE_REG_EDX, 28)
	FEAT_DEF(TM, 0x00000001, 0, RTE_REG_EDX, 29)
	FEAT_DEF(PBE, 0x00000001, 0, RTE_REG_EDX, 31)

	FEAT_DEF(DIGTEMP, 0x00000006, 0, RTE_REG_EAX,  0)
	FEAT_DEF(TRBOBST, 0x00000006, 0, RTE_REG_EAX,  1)
	FEAT_DEF(ARAT, 0x00000006, 0, RTE_REG_EAX,  2)
	FEAT_DEF(PLN, 0x00000006, 0, RTE_REG_EAX,  4)
	FEAT_DEF(ECMD, 0x00000006, 0, RTE_REG_EAX,  5)
	FEAT_DEF(PTM, 0x00000006, 0, RTE_REG_EAX,  6)

	FEAT_DEF(MPERF_APERF_MSR, 0x00000006, 0, RTE_REG_ECX,  0)
	FEAT_DEF(ACNT2, 0x00000006, 0, RTE_REG_ECX,  1)
	FEAT_DEF(ENERGY_EFF, 0x00000006, 0, RTE_REG_ECX,  3)

	FEAT_DEF(FSGSBASE, 0x00000007, 0, RTE_REG_EBX,  0)
	FEAT_DEF(BMI1, 0x00000007, 0, RTE_REG_EBX,  3)
	FEAT_DEF(HLE, 0x00000007, 0, RTE_REG_EBX,  4)
	FEAT_DEF(AVX2, 0x00000007, 0, RTE_REG_EBX,  5)
	FEAT_DEF(SMEP, 0x00000007, 0, RTE_REG_EBX,  7)
	FEAT_DEF(BMI2, 0x00000007, 0, RTE_REG_EBX,  8)
	FEAT_DEF(ERMS, 0x00000007, 0, RTE_REG_EBX,  9)
	FEAT_DEF(INVPCID, 0x00000007, 0, RTE_REG_EBX, 10)
	FEAT_DEF(RTM, 0x00000007, 0, RTE_REG_EBX, 11)
	FEAT_DEF(AVX512F, 0x00000007, 0, RTE_REG_EBX, 16)
	FEAT_DEF(AVX512DQ, 0x00000007, 0, RTE_REG_EBX, 17)
	FEAT_DEF(RDSEED, 0x00000007, 0, RTE_REG_EBX, 18)
	FEAT_DEF(AVX512IFMA, 0x00000007, 0, RTE_REG_EBX, 21)
	FEAT_DEF(AVX512CD, 0x00000007, 0, RTE_REG_EBX, 28)
	FEAT_DEF(AVX512BW, 0x00000007, 0, RTE_REG_EBX, 30)
	FEAT_DEF(AVX512VL, 0x00000007, 0, RTE_REG_EBX, 31)

	FEAT_DEF(AVX512VBMI, 0x00000007, 0, RTE_REG_ECX,  1)
	FEAT_DEF(WAITPKG, 0x00000007, 0, RTE_REG_ECX,  5)
	FEAT_DEF(AVX512VBMI2, 0x00000007, 0, RTE_REG_ECX,  6)
	FEAT_DEF(GFNI, 0x00000007, 0, RTE_REG_ECX,  8)
	FEAT_DEF(VAES, 0x00000007, 0, RTE_REG_ECX,  9)
	FEAT_DEF(VPCLMULQDQ, 0x00000007, 0, RTE_REG_ECX, 10)
	FEAT_DEF(AVX512VNNI, 0x00000007, 0, RTE_REG_ECX, 11)
	FEAT_DEF(AVX512BITALG, 0x00000007, 0, RTE_REG_ECX, 12)
	FEAT_DEF(AVX512VPOPCNTDQ, 0x00000007, 0, RTE_REG_ECX, 14)
	FEAT_DEF(CLDEMOTE, 0x00000007, 0, RTE_REG_ECX, 25)
	FEAT_DEF(MOVDIRI, 0x00000007, 0, RTE_REG_ECX, 27)
	FEAT_DEF(MOVDIR64B, 0x00000007, 0, RTE_REG_ECX, 28)

	FEAT_DEF(AVX512VP2INTERSECT, 0x00000007, 0, RTE_REG_EDX,  8)

	FEAT_DEF(LAHF_SAHF, 0x80000001, 0, RTE_REG_ECX,  0)
	FEAT_DEF(LZCNT, 0x80000001, 0, RTE_REG_ECX,  4)

	FEAT_DEF(SYSCALL, 0x80000001, 0, RTE_REG_EDX, 11)
	FEAT_DEF(XD, 0x80000001, 0, RTE_REG_EDX, 20)
	FEAT_DEF(1GB_PG, 0x80000001, 0, RTE_REG_EDX, 26)
	FEAT_DEF(RDTSCP, 0x80000001, 0, RTE_REG_EDX, 27)
	FEAT_DEF(EM64T, 0x80000001, 0, RTE_REG_EDX, 29)

	FEAT_DEF(INVTSC, 0x80000007, 0, RTE_REG_EDX,  8)
};

static int cpu_get_flag_enabled(enum rte_cpu_flag_t feature)
{
	const struct feature_entry *feat;
	cpuid_registers_t regs;
	unsigned int maxleaf;

	if (feature >= RTE_CPUFLAG_NUMFLAGS)
		/* Flag does not match anything in the feature tables */
		return -ENOENT;

	feat = &cpu_feature_table[feature];

	if (!feat->leaf)
		/* This entry in the table wasn't filled out! */
		return -EFAULT;

	maxleaf = __get_cpuid_max(feat->leaf & 0x80000000, NULL);

	if (maxleaf < feat->leaf)
		return 0;

	 __cpuid_count(feat->leaf, feat->subleaf,
		       regs[RTE_REG_EAX], regs[RTE_REG_EBX],
		       regs[RTE_REG_ECX], regs[RTE_REG_EDX]);

	/* check if the feature is enabled */
	return (regs[feat->reg] >> feat->bit) & 1;
}

static const char *cpu_get_flag_name(enum rte_cpu_flag_t feature)
{
	if (feature >= RTE_CPUFLAG_NUMFLAGS)
		return NULL;
	return cpu_feature_table[feature].name;
}

void _odp_cpu_flags_print_all(void)
{
	int len, i;
	int max_str = 1024;
	int max_len = max_str - 1;
	char str[max_str];

	len = snprintf(str, max_len, "\nCPU features supported:\n");

	for (i = 0; i < RTE_CPUFLAG_NUMFLAGS; i++) {
		if (cpu_get_flag_enabled(i) > 0)
			len += snprintf(&str[len], max_len - len, "%s ",
					cpu_get_flag_name(i));
	}

	len += snprintf(&str[len], max_len - len,
			"\n\nCPU features NOT supported:\n");

	for (i = 0; i < RTE_CPUFLAG_NUMFLAGS; i++) {
		if (cpu_get_flag_enabled(i) <= 0)
			len += snprintf(&str[len], max_len - len, "%s ",
					cpu_get_flag_name(i));
	}

	len += snprintf(&str[len], max_len - len, "\n\n");

	str[len] = '\0';
	_ODP_PRINT("%s", str);
}

int _odp_time_cpu_global_freq_is_const(void)
{
	if (odp_global_ro.system_info.cpu_constant_tsc ||
	    cpu_get_flag_enabled(RTE_CPUFLAG_INVTSC) > 0)
		return 1;

	_ODP_WARN("Assuming constant TSC based on CPU arch, but could not confirm from CPU "
		  "flags\n");

	return 1;
}

int _odp_cpu_flags_has_rdtsc(void)
{
	if (cpu_get_flag_enabled(RTE_CPUFLAG_TSC) > 0)
		return 1;

	return 0;
}
