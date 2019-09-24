/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/* this test makes sure that odp shared memory created with the ODP_SHM_PROC
 * flag is visible under linux, and checks that memory created with the
 * ODP_SHM_EXPORT flag is visible by other ODP instances.
 * It therefore checks both that the link
 * name under /dev/shm is correct, and also checks that the memory contents
 * is indeed shared.
 * we want:
 * -the odp test to run using C UNIT
 * -the main process to return the correct return code.
 *  (for the autotools test harness)
 *
 * To achieve this, the flow of operations is as follows:
 *
 *   linux process (main, non odp)	|
 *   (shmem_linux.c)			|
 *					|
 *					|
 *					|
 *   main()				|
 *   forks odp_app1 process		|
 *   wait for named pipe creation	|
 *					|
 *					|       ODP_APP1 process
 *					|       (shmem_odp1.c)
 *					|
 *					|  allocate shmem
 *					|  populate shmem
 *					|  create named pipe
 *					|  wait for test report in fifo...
 *   read shared memory			|
 *   check if memory contents is OK	|
 *   If not OK, write "F" in fifo and   |
 *   exit with failure code.            |      -------------------
 *                                      |
 *   forks odp app2 process             |       ODP APP2 process
 *   wait for child terminaison & status|       (shmem_odp2.c)
 *                                      |  lookup ODP_APP1 shared memory,
 *                                      |  check if memory contents is OK
 *                                      |  Exit(0) on success, exit(1) on fail
 *   If child failed, write "F" in fifo |
 *   exit with failure code.            |      -------------------
 *                                      |
 *   OK, write "S" in fifo,             |
 *   wait for child terminaison & status|
 *   terminate with same status as child|
 *					|       ODP APP1 process
 *					|       (shmem_odp1.c)
 *					|
 *					|   ...(continued)
 *					|   read S(success) or F(fail) from fifo
 *					|   report success or failure to C-Unit
 *					|   Exit(0) on success, exit(1) on fail
 *  wait for child terminaison & status	|
 *  terminate with same status as child	|
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
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <libgen.h>
#include <linux/limits.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdlib.h>
#include "shmem_linux.h"
#include "shmem_common.h"

#define ODP_APP1_NAME "shmem_odp1" /* name of the odp1 program, in this dir  */
#define ODP_APP2_NAME "shmem_odp2" /* name of the odp2 program, in this dir  */
/* odp-<pid>-shm-<name> */
#define DEVNAME_DEFAULT_DIR "/dev/shm"
#define DEVNAME_FMT "%s/%d/odp-%" PRIu64 "-shm-%s"
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
				uint32_t *flags, uint64_t *user_len,
				uint32_t *user_flags, uint32_t *align,
				uint64_t *offset)
{
	char shm_attr_filename[PATH_MAX];
	FILE *export_file;
	char *shm_dir = getenv("ODP_SHM_DIR");

	sprintf(shm_attr_filename, DEVNAME_FMT,
		shm_dir ? shm_dir : DEVNAME_DEFAULT_DIR,
		getuid(),
		ext_odp_pid, blockname);

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

	if (fscanf(export_file, "user_length: %" PRIu64 " ", user_len) != 1)
		goto export_file_read_err;

	if (fscanf(export_file, "user_flags: %" PRIu32 " ", user_flags) != 1)
		goto export_file_read_err;

	if (fscanf(export_file, "align: %" PRIu32 " ", align) != 1)
		goto export_file_read_err;

	if (fscanf(export_file, "offset: %" PRIu64 " ", offset) != 1)
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
	/* wait for the odp app1 to terminate */
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
	/* write "Failure" to the FIFO */
	nb_char = write(fd, &result, sizeof(char));
	close(fd);
	/* wait for the odp app1 to terminate */
	waitpid(odp_app, &status, 0);
	unlink(fifo_name);
	exit(1); /* error */
}

int main(int argc __attribute__((unused)), char *argv[])
{
	char prg_name[PATH_MAX];
	char odp_name1[PATH_MAX];
	char odp_name2[PATH_MAX];
	int nb_sec;
	int size;
	pid_t odp_app1;
	pid_t odp_app2;
	char *odp_params1 = NULL;
	char *odp_params2[3];
	char pid1[10];
	char fifo_name[PATH_MAX];  /* fifo for linux->odp feedback */
	int fifo_fd = -1;
	char shm_filename[PATH_MAX];/* shared mem device name, under /dev/shm */
	uint64_t len;
	uint64_t offset;
	uint32_t flags;
	uint64_t user_len;
	uint32_t user_flags;
	uint32_t align;
	int shm_fd;
	test_shared_linux_data_t *addr;
	int app2_status;
	uid_t uid = getuid();
	char *shm_dir = getenv("ODP_SHM_DIR");
	const char *exeext = getenv("EXEEXT");

	if (exeext == NULL)
		exeext = "";

	/* odp_app1 is in the same directory as this file: */
	strncpy(prg_name, argv[0], PATH_MAX - 1);
	sprintf(odp_name1, "%s/%s%s", dirname(prg_name), ODP_APP1_NAME, exeext);

	/* start the ODP application: */
	odp_app1 = fork();
	if (odp_app1 < 0)  /* error */
		exit(1);

	if (odp_app1 == 0) { /* child */
		execv(odp_name1, &odp_params1); /* no return unless error */
		fprintf(stderr, "execv failed: %s\n", strerror(errno));
	}

	/* wait max 30 sec for the fifo to be created by the ODP side.
	 * Just die if time expire as there is no fifo to communicate
	 * through... */
	sprintf(fifo_name, FIFO_NAME_FMT,
		shm_dir ? shm_dir : DEFAULT_SHM_DIR,
		uid, odp_app1);
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
	if (read_shmem_attribues(odp_app1, SHM_NAME,
				 shm_filename, &len, &flags,
				 &user_len, &user_flags, &align,
				 &offset) != 0) {
		printf("error read_shmem_attribues\n");
		test_failure(fifo_name, fifo_fd, odp_app1);
	}

	/* open the shm filename (which is either on /dev/shm/ or on hugetlbfs)
	 * O_CREAT flag not given => failure if shm_devname does not already
	 * exist */
	shm_fd = open(shm_filename, O_RDONLY,
		      S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (shm_fd == -1) {
		fprintf(stderr, "unable to open %s\n", shm_filename);
		test_failure(fifo_name, fifo_fd, odp_app1); /* no return */
	}

	/* linux ODP guarantees page size alignement. Larger alignment may
	 * fail as 2 different processes will have fully unrelated
	 * virtual spaces.
	 */
	size = sizeof(test_shared_linux_data_t);

	addr = mmap(NULL, size, PROT_READ, MAP_SHARED, shm_fd, offset);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "shmem_linux: mmap failed: %s\n",
			strerror(errno));
		test_failure(fifo_name, fifo_fd, odp_app1);
	}

	/* check that we see what the ODP application wrote in the memory */
	if ((addr->foo != TEST_SHARE_FOO) || (addr->bar != TEST_SHARE_BAR)) {
		fprintf(stderr, "ERROR: addr->foo %x addr->bar %x\n",
			addr->foo, addr->bar);
		test_failure(fifo_name, fifo_fd, odp_app1); /* no return */
	}

	/* odp_app2 is in the same directory as this file: */
	strncpy(prg_name, argv[0], PATH_MAX - 1);
	sprintf(odp_name2, "%s/%s%s", dirname(prg_name), ODP_APP2_NAME, exeext);

	/* start the second ODP application with pid of ODP_APP1 as parameter:*/
	sprintf(pid1, "%d", odp_app1);
	odp_params2[0] = odp_name2;
	odp_params2[1] = pid1;
	odp_params2[2] = NULL;
	odp_app2 = fork();
	if (odp_app2 < 0)  /* error */
		exit(1);

	if (odp_app2 == 0) { /* child */
		execv(odp_name2, odp_params2); /* no return unless error */
		fprintf(stderr, "execv failed: %s\n", strerror(errno));
	}

	/* wait for the second ODP application to terminate:
	 * status is OK if that second ODP application could see the
	 * memory shared by the first one. */
	waitpid(odp_app2, &app2_status, 0);

	if (app2_status)
		test_failure(fifo_name, fifo_fd, odp_app1); /* no return */

	/* everything looked good: */
	test_success(fifo_name, fifo_fd, odp_app1);
}
