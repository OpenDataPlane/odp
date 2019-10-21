/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <sched.h>
#include <pthread.h>

#include <odp/api/cpumask.h>
#include <odp/api/init.h>
#include <odp_debug_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>

#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <errno.h>
#include <sys/types.h>

/* Check that mask can hold all system CPUs*/
ODP_STATIC_ASSERT(ODP_CPUMASK_SIZE >= CPU_SETSIZE,
		  "ODP_CPUMASK_SIZE_TOO_SMALL");

/* Check that mask type is large enough */
ODP_STATIC_ASSERT(sizeof(odp_cpumask_t) >= sizeof(cpu_set_t),
		  "ODP_CPUMASK_T_TOO_SMALL");

void odp_cpumask_from_str(odp_cpumask_t *mask, const char *str_in)
{
	cpu_set_t cpuset;
	const char *str = str_in;
	const char *p;
	int cpu = 0;
	int len = strlen(str);

	CPU_ZERO(&cpuset);
	odp_cpumask_zero(mask);

	/* Strip leading "0x"/"0X" if present and verify length */
	if ((len >= 2) && ((str[1] == 'x') || (str[1] == 'X'))) {
		str += 2;
		len -= 2;
	}
	if (!len)
		return;

	/* Walk string from LSB setting cpu bits */
	for (p = str + len - 1; (len > 0) && (cpu < CPU_SETSIZE); p--, len--) {
		char c = *p;
		int value;
		int idx;

		/* Convert hex nibble, abort when invalid value found */
		if ((c >= '0') && (c <= '9'))
			value = c - '0';
		else if ((c >= 'A') && (c <= 'F'))
			value = c - 'A' + 10;
		else if ((c >= 'a') && (c <= 'f'))
			value = c - 'a' + 10;
		else
			return;

		/* Walk converted nibble and set bits in mask */
		for (idx = 0; idx < 4; idx++, cpu++)
			if (value & (1 << idx))
				CPU_SET(cpu, &cpuset);
	}

	/* Copy the computed mask */
	memcpy(mask, &cpuset, sizeof(cpuset));
}

int32_t odp_cpumask_to_str(const odp_cpumask_t *mask, char *str, int32_t len)
{
	char *p = str;
	int cpu = odp_cpumask_last(mask);
	int nibbles;
	int value;

	/* Handle bad string length, need at least 4 chars for "0x0" and
	 * terminating null char */
	if (len < 4)
		return -1; /* Failure */

	/* Handle no CPU found */
	if (cpu < 0) {
		strcpy(str, "0x0");
		return strlen(str) + 1; /* Success */
	}
	/* CPU was found and cpu >= 0 */

	/* Compute number of nibbles in cpumask that have bits set */
	nibbles = (cpu / 4) + 1;

	/* Verify minimum space (account for "0x" and termination) */
	if (len < (3 + nibbles))
		return -1; /* Failure */

	/* Prefix */
	*p++ = '0';
	*p++ = 'x';

	/*
	 * Now we can scan the cpus down to zero and
	 * build the string one nibble at a time
	 */
	value = 0;
	do {
		/* Set bit to go into the current nibble */
		if (CPU_ISSET(cpu, (const cpu_set_t *)mask))
			value |= 1 << (cpu % 4);

		/* If we are on a nibble boundary flush value to string */
		if (0 == (cpu % 4)) {
			if (value < 0xA)
				*p++ = '0' + value;
			else
				*p++ = 'A' + value - 0xA;
			value = 0;
		}
	} while (cpu--);

	/* Terminate the string */
	*p++ = 0;
	return p - str; /* Success */
}

void odp_cpumask_zero(odp_cpumask_t *mask)
{
	CPU_ZERO((cpu_set_t *)mask);
}

void odp_cpumask_set(odp_cpumask_t *mask, int cpu)
{
	CPU_SET(cpu, (cpu_set_t *)mask);
}

void odp_cpumask_setall(odp_cpumask_t *mask)
{
	int cpu;

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++)
		CPU_SET(cpu, (cpu_set_t *)mask);
}

void odp_cpumask_clr(odp_cpumask_t *mask, int cpu)
{
	CPU_CLR(cpu, (cpu_set_t *)mask);
}

int odp_cpumask_isset(const odp_cpumask_t *mask, int cpu)
{
	return CPU_ISSET(cpu, (const cpu_set_t *)mask);
}

int odp_cpumask_count(const odp_cpumask_t *mask)
{
	return CPU_COUNT((const cpu_set_t *)mask);
}

void odp_cpumask_and(odp_cpumask_t *dest, const odp_cpumask_t *src1,
		     const odp_cpumask_t *src2)
{
	CPU_AND((cpu_set_t *)dest, (const cpu_set_t *)src1,
		(const cpu_set_t *)src2);
}

void odp_cpumask_or(odp_cpumask_t *dest, const odp_cpumask_t *src1,
		    const odp_cpumask_t *src2)
{
	CPU_OR((cpu_set_t *)dest, (const cpu_set_t *)src1,
	       (const cpu_set_t *)src2);
}

void odp_cpumask_xor(odp_cpumask_t *dest, const odp_cpumask_t *src1,
		     const odp_cpumask_t *src2)
{
	CPU_XOR((cpu_set_t *)dest, (const cpu_set_t *)src1,
		(const cpu_set_t *)src2);
}

int odp_cpumask_equal(const odp_cpumask_t *mask1,
		      const odp_cpumask_t *mask2)
{
	return CPU_EQUAL((const cpu_set_t *)mask1, (const cpu_set_t *)mask2);
}

void odp_cpumask_copy(odp_cpumask_t *dest, const odp_cpumask_t *src)
{
	memcpy(dest, src, sizeof(odp_cpumask_t));
}

int odp_cpumask_first(const odp_cpumask_t *mask)
{
	int cpu;

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++)
		if (odp_cpumask_isset(mask, cpu))
			return cpu;
	return -1;
}

int odp_cpumask_last(const odp_cpumask_t *mask)
{
	int cpu;

	for (cpu = CPU_SETSIZE - 1; cpu >= 0; cpu--)
		if (odp_cpumask_isset(mask, cpu))
			return cpu;
	return -1;
}

int odp_cpumask_next(const odp_cpumask_t *mask, int cpu)
{
	for (cpu += 1; cpu < CPU_SETSIZE; cpu++)
		if (odp_cpumask_isset(mask, cpu))
			return cpu;
	return -1;
}

/*
 * This function obtains system information specifying which cpus are
 * available at boot time.
 */
static int get_available_cpus(void)
{
	int cpu_idnum;
	cpu_set_t cpuset;
	int ret;

	/* Clear the global cpumasks for control and worker CPUs */
	odp_cpumask_zero(&odp_global_ro.control_cpus);
	odp_cpumask_zero(&odp_global_ro.worker_cpus);

	CPU_ZERO(&cpuset);
	ret = sched_getaffinity(0, sizeof(cpuset), &cpuset);

	if (ret < 0) {
		ODP_ERR("Failed to get cpu affinity");
			return -1;
	}

	for (cpu_idnum = 0; cpu_idnum < CPU_SETSIZE - 1; cpu_idnum++) {
		if (CPU_ISSET(cpu_idnum, &cpuset)) {
			odp_global_ro.num_cpus_installed++;
			/* Add the CPU to our default cpumasks */
			odp_cpumask_set(&odp_global_ro.control_cpus,
					(int)cpu_idnum);
			odp_cpumask_set(&odp_global_ro.worker_cpus,
					(int)cpu_idnum);
		}
	}

	return 0;
}

/*
 * This function creates reasonable default cpumasks for control tasks
 * from the set of CPUs available at boot time.
 * This function assumes that the global control cpumask contains
 * a list of all installed CPUs, and that no control cpumask was specified.
 */
static void init_default_control_cpumask(int worker_cpus_default)
{
	odp_cpumask_t *control_mask = &odp_global_ro.control_cpus;
	odp_cpumask_t *worker_mask = &odp_global_ro.worker_cpus;
	int i;

	/* (Bits for all available CPUs are SET in control cpumask) */

	if (worker_cpus_default) {
		/*
		 * The worker cpumask was also unspecified...
		 * If only one or two CPUs installed, use CPU 0 for control.
		 * Otherwise leave it for the kernel and start with CPU 1.
		 */
		if (odp_global_ro.num_cpus_installed < 3) {
			/*
			 * If only two CPUS, use CPU 0 for control and
			 * use CPU 1 for workers.
			 */
			odp_cpumask_clr(control_mask, 1);
		} else {
			/*
			 * If three or more CPUs, reserve CPU 0 for kernel,
			 * reserve CPU 1 for control, and
			 * reserve remaining CPUs for workers
			 */
			odp_cpumask_clr(control_mask, 0);
			for (i = 2; i < odp_global_ro.num_cpus_installed; i++)
				if (odp_cpumask_isset(worker_mask, i))
					odp_cpumask_clr(control_mask, i);
		}
	} else {
		/*
		 * The worker cpumask was specified so first ensure
		 * the control cpumask does not overlap any worker CPUs
		 */
		for (i = 0; i < odp_global_ro.num_cpus_installed; i++)
			if (odp_cpumask_isset(worker_mask, i))
				odp_cpumask_clr(control_mask, i);

		/*
		 * If only one or two CPUs installed,
		 * ensure availability of CPU 0 for control threads
		 */
		if (odp_global_ro.num_cpus_installed < 3) {
			odp_cpumask_set(control_mask, 0);
			odp_cpumask_clr(control_mask, 1);
		} else {
			/*
			 * If three or more CPUs installed,
			 * then use CPU 0 for control threads if
			 * CPU 1 was allocated for workers - otherwise
			 * use CPU 1 for control and don't use CPU 0
			 */
			if (odp_cpumask_isset(worker_mask, 1))
				odp_cpumask_set(control_mask, 0);
			else
				odp_cpumask_clr(control_mask, 0);
		}
	}
}

/*
 * This function creates reasonable default cpumasks for worker tasks
 * from the set of CPUs available at boot time.
 * This function assumes that the global worker cpumask contains
 * a list of all installed CPUs, and that no worker cpumask was specified.
 */
static void init_default_worker_cpumask(int control_cpus_default)
{
	odp_cpumask_t *control_mask = &odp_global_ro.control_cpus;
	odp_cpumask_t *worker_mask = &odp_global_ro.worker_cpus;
	int i;

	/* (Bits for all available CPUs are SET in worker cpumask) */

	if (control_cpus_default) {
		/*
		 * The control cpumask was also unspecified...
		 * CPU 0 is only used for workers on uniprocessor systems
		 */
		if (odp_global_ro.num_cpus_installed > 1)
			odp_cpumask_clr(worker_mask, 0);

		if (odp_global_ro.num_cpus_installed > 2)
			/*
			 * If three or more CPUs, reserve CPU 0 for kernel,
			 * reserve CPU 1 for control, and
			 * reserve remaining CPUs for workers
			 */
			odp_cpumask_clr(worker_mask, 1);
	} else {
		/*
		 * The control cpumask was specified so first ensure
		 * the worker cpumask does not overlap any control CPUs
		 */
		for (i = 0; i < odp_global_ro.num_cpus_installed; i++)
			if (odp_cpumask_isset(control_mask, i))
				odp_cpumask_clr(worker_mask, i);

		/*
		 * If only one CPU installed, use CPU 0 for workers
		 * even though it is used for control as well.
		 */
		if (odp_global_ro.num_cpus_installed < 2)
			odp_cpumask_set(worker_mask, 0);
		else
			odp_cpumask_clr(worker_mask, 0);
	}
}

/*
 * This function creates reasonable default cpumasks for control and worker
 * tasks from the set of CPUs available at boot time.
 * It also allows the default cpumasks to be overridden by
 * externally specified cpumasks passed in as initialization parameters.
 */
int _odp_cpumask_init_global(const odp_init_t *params)
{
	odp_cpumask_t *control_mask = &odp_global_ro.control_cpus;
	odp_cpumask_t *worker_mask = &odp_global_ro.worker_cpus;
	odp_cpumask_t check_mask;
	int control_cpus_default = 1;
	int worker_cpus_default = 1;

	/*
	 * Initialize the global control and worker cpumasks with lists of
	 * all installed CPUs.  Return an error if this procedure fails.
	 */
	if (!get_available_cpus()) {
		if (params) {
			if (params->control_cpus) {
				/*
				 * If uninstalled control CPUs were specified,
				 * then return an error.  Otherwise copy the
				 * specified control cpumask into the global
				 * control cpumask for later reference.
				 */
				odp_cpumask_and(&check_mask, control_mask,
						params->control_cpus);
				if (odp_cpumask_equal(params->control_cpus,
						      &check_mask)) {
					odp_cpumask_copy(control_mask,
							 params->control_cpus);
					control_cpus_default = 0;
				} else {
					return -1;
				}
			}
			if (params->worker_cpus) {
				/*
				 * If uninstalled worker CPUs were specified,
				 * then return an error.  Otherwise copy the
				 * specified worker cpumask into the global
				 * worker cpumask for later reference.
				 */
				odp_cpumask_and(&check_mask, worker_mask,
						params->worker_cpus);
				if (odp_cpumask_equal(params->worker_cpus,
						      &check_mask)) {
					odp_cpumask_copy(worker_mask,
							 params->worker_cpus);
					worker_cpus_default = 0;
				} else {
					return -1;
				}
			}
		}

		/*
		 * Any caller-specified cpumasks have been validated
		 * and saved.  Now fill in any unspecified masks with
		 * 'best guess' default configurations.
		 * (Worker mask gets to allocate CPUs before control mask)
		 */
		if (worker_cpus_default)
			init_default_worker_cpumask(control_cpus_default);
		if (control_cpus_default)
			init_default_control_cpumask(worker_cpus_default);

		return 0;
	} else {
		return -1;
	}
}

int _odp_cpumask_term_global(void)
{
	return 0;
}
