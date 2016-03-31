/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <sched.h>
#include <pthread.h>

#include <odp/api/cpumask.h>
#include <odp_debug_internal.h>

#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <errno.h>
#include <sys/types.h>

/** @internal Compile time assert */
_ODP_STATIC_ASSERT(CPU_SETSIZE >= ODP_CPUMASK_SIZE,
		   "ODP_CPUMASK_SIZE__SIZE_ERROR");

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
	memcpy(&mask->set, &cpuset, sizeof(cpuset));
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
		if (CPU_ISSET(cpu, &mask->set))
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
	CPU_ZERO(&mask->set);
}

void odp_cpumask_set(odp_cpumask_t *mask, int cpu)
{
	CPU_SET(cpu, &mask->set);
}

void odp_cpumask_setall(odp_cpumask_t *mask)
{
	int cpu;

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++)
		CPU_SET(cpu, &mask->set);
}

void odp_cpumask_clr(odp_cpumask_t *mask, int cpu)
{
	CPU_CLR(cpu, &mask->set);
}

int odp_cpumask_isset(const odp_cpumask_t *mask, int cpu)
{
	return CPU_ISSET(cpu, &mask->set);
}

int odp_cpumask_count(const odp_cpumask_t *mask)
{
	return CPU_COUNT(&mask->set);
}

void odp_cpumask_and(odp_cpumask_t *dest, const odp_cpumask_t *src1,
		     const odp_cpumask_t *src2)
{
	CPU_AND(&dest->set, &src1->set, &src2->set);
}

void odp_cpumask_or(odp_cpumask_t *dest, const odp_cpumask_t *src1,
		    const odp_cpumask_t *src2)
{
	CPU_OR(&dest->set, &src1->set, &src2->set);
}

void odp_cpumask_xor(odp_cpumask_t *dest, const odp_cpumask_t *src1,
		     const odp_cpumask_t *src2)
{
	CPU_XOR(&dest->set, &src1->set, &src2->set);
}

int odp_cpumask_equal(const odp_cpumask_t *mask1,
		      const odp_cpumask_t *mask2)
{
	return CPU_EQUAL(&mask1->set, &mask2->set);
}

void odp_cpumask_copy(odp_cpumask_t *dest, const odp_cpumask_t *src)
{
	memcpy(&dest->set, &src->set, sizeof(src->set));
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
 * available at boot time. These data are then used to produce cpumasks of
 * configured CPUs without concern over isolation support.
 */
static int get_installed_cpus(void)
{
	char *numptr;
	char *endptr;
	long int cpu_idnum;
	DIR  *d;
	struct dirent *dir;

	/* Clear the global cpumasks for control and worker CPUs */
	odp_cpumask_zero(&odp_global_data.control_cpus);
	odp_cpumask_zero(&odp_global_data.worker_cpus);

	/*
	 * Scan the /sysfs pseudo-filesystem for CPU info directories.
	 * There should be one subdirectory for each installed logical CPU
	 */
	d = opendir("/sys/devices/system/cpu");
	if (d) {
		while ((dir = readdir(d)) != NULL) {
			cpu_idnum = CPU_SETSIZE;

			/*
			 * If the current directory entry doesn't represent
			 * a CPU info subdirectory then skip to the next entry.
			 */
			if (dir->d_type == DT_DIR) {
				if (!strncmp(dir->d_name, "cpu", 3)) {
					/*
					 * Directory name starts with "cpu"...
					 * Try to extract a CPU ID number
					 * from the remainder of the dirname.
					 */
					errno = 0;
					numptr = dir->d_name;
					numptr += 3;
					cpu_idnum = strtol(numptr, &endptr,
							   10);
					if (errno || (endptr == numptr))
						continue;
				} else {
					continue;
				}
			} else {
				continue;
			}
			/*
			 * If we get here the current directory entry specifies
			 * a CPU info subdir for the CPU indexed by cpu_idnum.
			 */

			/* Track number of logical CPUs discovered */
			if (odp_global_data.num_cpus_installed <
			    (int)(cpu_idnum + 1))
				odp_global_data.num_cpus_installed =
						(int)(cpu_idnum + 1);

			/* Add the CPU to our default cpumasks */
			odp_cpumask_set(&odp_global_data.control_cpus,
					(int)cpu_idnum);
			odp_cpumask_set(&odp_global_data.worker_cpus,
					(int)cpu_idnum);
		}
		closedir(d);
		return 0;
	} else {
		return -1;
	}
}

/*
 * This function creates reasonable default cpumasks for control and worker
 * tasks from the set of CPUs available at boot time.
 */
int odp_cpumask_init_global(void)
{
	odp_cpumask_t *control_mask = &odp_global_data.control_cpus;
	odp_cpumask_t *worker_mask = &odp_global_data.worker_cpus;
	int i;
	int retval = -1;

	if (!get_installed_cpus()) {
		/* CPU 0 is only used for workers on uniprocessor systems */
		if (odp_global_data.num_cpus_installed > 1)
			odp_cpumask_clr(worker_mask, 0);
		/*
		 * If only one or two CPUs installed, use CPU 0 for control.
		 * Otherwise leave it for the kernel and start with CPU 1.
		 */
		if (odp_global_data.num_cpus_installed < 3) {
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
			odp_cpumask_clr(worker_mask, 1);
			for (i = 2; i < CPU_SETSIZE; i++) {
				if (odp_cpumask_isset(worker_mask, i))
					odp_cpumask_clr(control_mask, i);
			}
		}
		retval = 0;
	}
	return retval;
}

int odp_cpumask_term_global(void)
{
	return 0;
}
