/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2020, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP system information
 */

#ifndef ODP_API_SPEC_SYSTEM_INFO_H_
#define ODP_API_SPEC_SYSTEM_INFO_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_system ODP SYSTEM
 *  System information.
 *  @{
 */

/**
 * CPU instruction set architecture (ISA) families
 */
typedef enum odp_cpu_arch_t {
	/** Unknown CPU architecture */
	ODP_CPU_ARCH_UNKNOWN = 0,

	/** ARM */
	ODP_CPU_ARCH_ARM,

	/** MIPS */
	ODP_CPU_ARCH_MIPS,

	/** PowerPC */
	ODP_CPU_ARCH_PPC,

	/** RISC-V */
	ODP_CPU_ARCH_RISCV,

	/** x86 */
	ODP_CPU_ARCH_X86

} odp_cpu_arch_t;

/**
 * ARM ISA versions
 *
 * ISA versions are defined in ascending order.
 */
typedef enum odp_cpu_arch_arm_t {
	/** Unknown ARM ISA version */
	ODP_CPU_ARCH_ARM_UNKNOWN = 0,

	/** ARMv6 ISA */
	ODP_CPU_ARCH_ARMV6,

	/** ARMv7-A ISA */
	ODP_CPU_ARCH_ARMV7,

	/** ARMv8.0-A ISA */
	ODP_CPU_ARCH_ARMV8_0,

	/** ARMv8.1-A ISA */
	ODP_CPU_ARCH_ARMV8_1,

	/** ARMv8.2-A ISA */
	ODP_CPU_ARCH_ARMV8_2,

	/** ARMv8.3-A ISA */
	ODP_CPU_ARCH_ARMV8_3,

	/** ARMv8.4-A ISA */
	ODP_CPU_ARCH_ARMV8_4,

	/** ARMv8.5-A ISA */
	ODP_CPU_ARCH_ARMV8_5,

	/** ARMv8.6-A ISA */
	ODP_CPU_ARCH_ARMV8_6,

} odp_cpu_arch_arm_t;

/**
 * MIPS ISA versions
 */
typedef enum odp_cpu_arch_mips_t {
	/** Unknown MIPS ISA version */
	ODP_CPU_ARCH_MIPS_UNKNOWN = 0

} odp_cpu_arch_mips_t;

/**
 * PowerPC ISA versions
 */
typedef enum odp_cpu_arch_ppc_t {
	/** Unknown PPC ISA version */
	ODP_CPU_ARCH_PPC_UNKNOWN = 0

} odp_cpu_arch_ppc_t;

/**
 * RISC-V ISA versions
 */
typedef enum odp_cpu_arch_riscv_t {
	/** Unknown RISC-V ISA version */
	ODP_CPU_ARCH_RISCV_UNKNOWN = 0

} odp_cpu_arch_riscv_t;

/**
 * x86 ISA versions
 */
typedef enum odp_cpu_arch_x86_t {
	/** Unknown x86 ISA version */
	ODP_CPU_ARCH_X86_UNKNOWN = 0,

	/** x86 32bit ISA */
	ODP_CPU_ARCH_X86_I686,

	/** x86 64bit ISA */
	ODP_CPU_ARCH_X86_64

} odp_cpu_arch_x86_t;

/**
 * CPU ISA versions
 */
typedef union odp_cpu_arch_isa_t {
	/** ARM ISA versions */
	odp_cpu_arch_arm_t arm;

	/** MIPS ISA versions */
	odp_cpu_arch_mips_t mips;

	/** PowerPC ISA versions */
	odp_cpu_arch_ppc_t ppc;

	/** RISC-V ISA versions */
	odp_cpu_arch_riscv_t riscv;

	/** x86 ISA versions */
	odp_cpu_arch_x86_t x86;

} odp_cpu_arch_isa_t;

/**
 * System info
 */
typedef struct odp_system_info_t {
	/**
	 * CPU architecture
	 *
	 * Defines CPU ISA family: ARM, MIPS, PPC, RISC-V, x86 or unknown
	 */
	odp_cpu_arch_t cpu_arch;

	/**
	 * ISA version of ODP software
	 *
	 * Defines the ISA version that was used to build the ODP library. Depending on compiler
	 * target architecture setting, the value may be lower than the ISA version supported by
	 * the CPU hardware.
	 */
	odp_cpu_arch_isa_t cpu_isa_sw;

	/**
	 * ISA version of CPU hardware
	 *
	 * Defines the ISA version supported by the CPU hardware. The value is set to
	 * ODP_CPU_ARCH_<arch>_UNKNOWN, when the ISA version cannot be determined.
	 */
	odp_cpu_arch_isa_t cpu_isa_hw;

} odp_system_info_t;

/**
 * Retrieve system information
 *
 * Fills in system information structure on success. The call is not intended
 * for fast path use.
 *
 * @param[out] info    Pointer to system info struct for output
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_system_info(odp_system_info_t *info);

/**
 * Default system huge page size in bytes
 *
 * @return Default huge page size in bytes
 * @retval 0 on no huge pages
 */
uint64_t odp_sys_huge_page_size(void);

/**
 * System huge page sizes in bytes
 *
 * Returns the number of huge page sizes supported by the system. Outputs up to
 * 'num' sizes when the 'size' array pointer is not NULL. If return value is
 * larger than 'num', there are more supported sizes than the function was
 * allowed to output. If return value (N) is less than 'num', only sizes
 * [0 ... N-1] have been written. Returned values are ordered from smallest to
 * largest.
 *
 * @param[out] size     Points to an array of huge page sizes for output
 * @param      num      Maximum number of huge page sizes to output
 *
 * @return Number of supported huge page sizes
 * @retval <0 on failure
 */
int odp_sys_huge_page_size_all(uint64_t size[], int num);

/**
 * Page size in bytes
 *
 * @return Page size in bytes
 */
uint64_t odp_sys_page_size(void);

/**
 * Cache line size in bytes
 *
 * @return CPU cache line size in bytes
 */
int odp_sys_cache_line_size(void);

/**
 * Print system info
 *
 * Print out implementation defined information about the system. This
 * information is intended for debugging purposes and may contain e.g.
 * information about CPUs, memory and other HW configuration.
 */
void odp_sys_info_print(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
