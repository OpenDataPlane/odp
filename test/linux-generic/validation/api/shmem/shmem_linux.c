/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/* this test makes sure that odp shared memory created with the ODP_SHM_PROC
 * flag is visible under linux. It therefore checks both that the device
 * name under /dev/shm is correct, and also checks that the memory contents
 * is indeed shared.
 * we want:
 * -the odp test to run using C UNIT
 * -the main process to return the correct return code.
 *  (for the autotools test harness)
 *
 * To achieve this, the flow of operations is as follows:
 *
 *   linux process (main, non odp)	|	ODP process
 *   (shmem_linux.c)			|	(shmem_odp.c)
 *					|
 *   main()				|
 *   forks odp process			|  allocate shmem
 *   wait for named pipe creation	|  populate shmem
 *					|  create named pipe
 *   read shared memory			|  wait for test report in fifo
 *   check if memory contents is OK	|
 *   if OK, write "S" in fifo, else "F" |  report success or failure to C-Unit
 *   wait for child terminaison & status|  terminate with usual F/S status
 *   terminate with same status as child|
 *					|
 *				       \|/
 *				      time
 */

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <libgen.h>
#include <linux/limits.h>
#include <inttypes.h>
#include "shmem_linux.h"
#include "shmem_common.h"

#define ODP_APP_NAME "shmem_odp" /* name of the odp program, in this dir     */
#define DEVNAME_FMT "/tmp/odp-%" PRIu64 "-shm-%s"  /* odp-<pid>-shm-<name>   */
#define MAX_FIFO_WAIT 30         /* Max time waiting for the fifo (sec)      */

/*
 * read the attributes of a externaly shared mem object:
 * input: ext_odp_pid, blockname: the remote ODP instance and the exported
 *				  block name to be searched.
 * Output: filename: the memory block underlaying file to be opened
 *		     (the given buffer should be big enough i.e. at
 *		      least ISHM_FILENAME_MAXLEN bytes)
 *   The 3 following parameters are really here for debug
 *   as they are really meaningles in a non-odp process:
 *	   len: the block real length (bytes, multiple of page sz)
 *	   flags: the _ishm flags setting the block was created with
 *	   align: the alignement setting the block was created with
 *
 * return 0 on success, non zero on error
 */
static int read_shmem_attribues(uint64_t ext_odp_pid, const char *blockname,
				char *filename, uint64_t *len,
				uint32_t *flags, uint32_t *align)
{
	char shm_attr_filename[PATH_MAX];
	FILE *export_file;

	sprintf(shm_attr_filename, DEVNAME_FMT, ext_odp_pid, blockname);

	/* O_CREAT flag not given => failure if shm_attr_filename does not
	 * already exist */
	export_file = fopen(shm_attr_filename, "r");
	if (export_file == NULL)
		return -1;

	if (fscanf(export_file, "ODP exported shm block info: ") != 0)
		goto export_file_read_err;

	if (fscanf(export_file, "ishm_blockname: %*s ") != 0)
		goto export_file_read_err;

	if (fscanf(export_file, "file: %s ", filename) != 1)
		goto export_file_read_err;

	if (fscanf(export_file, "length: %" PRIu64 " ", len) != 1)
		goto export_file_read_err;

	if (fscanf(export_file, "flags: %" PRIu32 " ", flags) != 1)
		goto export_file_read_err;

	if (fscanf(export_file, "align: %" PRIu32 " ", align) != 1)
		goto export_file_read_err;

	fclose(export_file);
	return 0;

export_file_read_err:
	fclose(export_file);
	return -1;
}

void test_success(char *fifo_name, int fd, pid_t odp_app)
{
	int status;
	int nb_char;
	char result = TEST_SUCCESS;
	/* write "Success" to the FIFO */
	nb_char = write(fd, &result, sizeof(char));
	close(fd);
	/* wait for the odp app to terminate */
	waitpid(odp_app, &status, 0);
	/* if the write failed, report an error anyway */
	if (nb_char != 1)
		status = 1;
	unlink(fifo_name);
	exit(status);	/* the status reported by the odp side is returned */
}

void test_failure(char *fifo_name, int fd, pid_t odp_app)
{
	int status;
	char result;

	int nb_char __attribute__((unused)); /*ignored: we fail anyway */

	result = TEST_FAILURE;
	/* write "Success" to the FIFO */
	nb_char = write(fd, &result, sizeof(char));
	close(fd);
	/* wait for the odp app to terminate */
	waitpid(odp_app, &status, 0);
	unlink(fifo_name);
	exit(1); /* error */
}

int main(int argc __attribute__((unused)), char *argv[])
{
	char prg_name[PATH_MAX];
	char odp_name[PATH_MAX];
	int nb_sec;
	uint64_t size;
	pid_t odp_app;
	char *odp_params = NULL;
	char fifo_name[PATH_MAX];  /* fifo for linux->odp feedback */
	int fifo_fd = -1;
	char shm_devname[PATH_MAX];/* shared mem device name.*/
	uint64_t len;
	uint32_t flags;
	uint32_t align;
	int shm_fd;
	test_shared_linux_data_t *addr;

	/* odp app is in the same directory as this file: */
	strncpy(prg_name, argv[0], PATH_MAX - 1);
	sprintf(odp_name, "%s/%s", dirname(prg_name), ODP_APP_NAME);

	/* start the ODP application: */
	odp_app = fork();
	if (odp_app < 0)  /* error */
		exit(1);

	if (odp_app == 0) /* child */
		execv(odp_name, &odp_params);

	/* wait max 30 sec for the fifo to be created by the ODP side.
	 * Just die if time expire as there is no fifo to communicate
	 * through... */
	sprintf(fifo_name, FIFO_NAME_FMT, odp_app);
	for (nb_sec = 0; nb_sec < MAX_FIFO_WAIT; nb_sec++) {
		fifo_fd = open(fifo_name, O_WRONLY);
		if (fifo_fd >= 0)
			break;
		sleep(1);
	}
	if (fifo_fd < 0)
		exit(1);
	printf("pipe found\n");

	/* the linux named pipe has now been found, meaning that the
	 * ODP application is up and running, and has allocated shmem.
	 * check to see if linux can see the created shared memory: */

	/* read the shared memory attributes (includes the shm filename): */
	if (read_shmem_attribues(odp_app, ODP_SHM_NAME,
				 shm_devname, &len, &flags, &align) != 0)
		test_failure(fifo_name, fifo_fd, odp_app);

	/* open the shm filename (which is either on /tmp or on hugetlbfs)
	 * O_CREAT flag not given => failure if shm_devname does not already
	 * exist */
	shm_fd = open(shm_devname, O_RDONLY,
		      S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (shm_fd == -1)
		test_failure(fifo_name, fifo_fd, odp_app);

	/* linux ODP guarantees page size alignement. Larger alignment may
	 * fail as 2 different processes will have fully unrelated
	 * virtual spaces.
	 */
	size = sizeof(test_shared_linux_data_t);

	addr = mmap(NULL, size, PROT_READ, MAP_SHARED, shm_fd, 0);
	if (addr == MAP_FAILED)
		test_failure(fifo_name, fifo_fd, odp_app);

	/* check that we see what the ODP application wrote in the memory */
	if ((addr->foo == TEST_SHARE_FOO) && (addr->bar == TEST_SHARE_BAR))
		test_success(fifo_name, fifo_fd, odp_app);
	else
		test_failure(fifo_name, fifo_fd, odp_app);
}
