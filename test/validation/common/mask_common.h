/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_MASK_COMMON_H_
#define ODP_MASK_COMMON_H_

unsigned mask_capacity(void);

void cpumask_test_odp_cpumask_to_from_str(void);
void cpumask_test_odp_cpumask_equal(void);
void cpumask_test_odp_cpumask_zero(void);
void cpumask_test_odp_cpumask_set(void);
void cpumask_test_odp_cpumask_clr(void);
void cpumask_test_odp_cpumask_isset(void);
void cpumask_test_odp_cpumask_count(void);
void cpumask_test_odp_cpumask_and(void);
void cpumask_test_odp_cpumask_or(void);
void cpumask_test_odp_cpumask_xor(void);
void cpumask_test_odp_cpumask_copy(void);
void cpumask_test_odp_cpumask_first(void);
void cpumask_test_odp_cpumask_last(void);
void cpumask_test_odp_cpumask_next(void);
void cpumask_test_odp_cpumask_setall(void);

#endif
