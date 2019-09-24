/* Copyright (c) 2019, Nokia
 * Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/* This file handles the internal shared memory: internal shared memory
 * is memory which is sharable by all ODP threads regardless of how the
 * ODP thread is implemented (pthread or process) and regardless of fork()
 * time.
 * Moreover, when reserved with the _ODP_ISHM_SINGLE_VA flag,
 * internal shared memory is guaranteed to always be located at the same virtual
 * address, i.e. pointers to internal shared memory are fully shareable
 * between odp threads (regardless of thread type or fork time) in that case.
 * Internal shared memory is mainly meant to be used internally within ODP
 * (hence its name), but may also be allocated by odp applications and drivers,
 * in the future (through these interfaces).
 * To guarantee this full pointer shareability (when reserved with the
 * _ODP_ISHM_SINGLE_VA flag) the whole internal shared memory area is reserved
 * at global_init time.
 * Because all ODP threads (pthreads or processes) are descendants of the ODP
 * instantiation process, this address space is inherited by all ODP threads.
 * When internal shmem reservation actually occurs, and when reserved with the
 * _ODP_ISHM_SINGLE_VA flag, memory is allocated from the pre-reserved single
 * VA memory.
 * When an internal shared memory block is released, the memory is returned to
 * its "pool" of pre-reserved memory (assuming it was allocated from there). The
 * memory is not returned back to kernel until odp_term_global().
 *
 * This file contains functions to handle the VA area (handling fragmentation
 * and defragmentation resulting from different allocs/release) and also
 * define the functions to allocate, release and lookup internal shared
 * memory:
 *  _odp_ishm_reserve(), _odp_ishm_free*() and _odp_ishm_lookup*()...
 */
#include <odp_posix_extensions.h>
#include <odp_config_internal.h>
#include <odp_global_data.h>
#include <odp/api/spinlock.h>
#include <odp/api/align.h>
#include <odp/api/system_info.h>
#include <odp/api/debug.h>
#include <odp_init_internal.h>
#include <odp_errno_define.h>
#include <odp_shm_internal.h>
#include <odp_debug_internal.h>
#include <odp_align_internal.h>
#include <odp_fdserver_internal.h>
#include <odp_shm_internal.h>
#include <odp_ishmphy_internal.h>
#include <odp_ishmpool_internal.h>
#include <odp_libconfig_internal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/types.h>
#include <inttypes.h>
#include <sys/wait.h>
#include <libgen.h>
#include <sys/types.h>
#include <dirent.h>

/*
 * Maximum number of internal shared memory blocks.
 *
 * This is the number of separate ISHM areas that can be reserved concurrently
 * (Note that freeing such blocks may take time, or possibly never happen
 * if some of the block owners never procsync() after free). This number
 * should take that into account)
 */
#define ISHM_MAX_NB_BLOCKS 128

/*
 * Maximum internal shared memory block name length in chars
 * probably taking the same number as SHM name size make sense at this stage
 */
#define ISHM_NAME_MAXLEN 128

/*
 * Linux underlying file name: <directory>/odp-<odp_pid>-ishm-<name>
 * The <name> part may be replaced by a sequence number if no specific
 * name is given at reserve time
 * <directory> is either /dev/shm or the hugepagefs mount point for default
 * size.
 * (searched at init time)
 */
#define ISHM_FILENAME_MAXLEN (ISHM_NAME_MAXLEN + 64)
#define ISHM_FILENAME_FORMAT "%s/odp-%d-ishm-%s"
#define ISHM_FILENAME_NORMAL_PAGE_DIR "/dev/shm"
#define _ODP_FILES_FMT "odp-%d-"

/*
 * when the memory is to be shared with an external entity (such as another
 * ODP instance or an OS process not part of this ODP instance) then a
 * export file is created describing the exported memory: this defines the
 * location and the filename format of this description file
 */
#define ISHM_EXPTNAME_FORMAT "%s/%s/odp-%d-shm-%s"

/*
 * At worse case the virtual space gets so fragmented that there is
 * a unallocated fragment between each allocated fragment:
 * In that case, the number of fragments to take care of is twice the
 * number of ISHM blocks + 1.
 */
#define ISHM_NB_FRAGMNTS (ISHM_MAX_NB_BLOCKS * 2 + 1)

/*
 * when a memory block is to be exported outside its ODP instance,
 * an block 'attribute file' is created in /dev/shm/odp-<pid>-shm-<name>.
 * The information given in this file is according to the following:
 */
#define EXPORT_FILE_LINE1_FMT "ODP exported shm block info:"
#define EXPORT_FILE_LINE2_FMT "ishm_blockname: %s"
#define EXPORT_FILE_LINE3_FMT "file: %s"
#define EXPORT_FILE_LINE4_FMT "length: %" PRIu64
#define EXPORT_FILE_LINE5_FMT "flags: %" PRIu32
#define EXPORT_FILE_LINE6_FMT "user_length: %" PRIu64
#define EXPORT_FILE_LINE7_FMT "user_flags: %" PRIu32
#define EXPORT_FILE_LINE8_FMT "align: %" PRIu32
#define EXPORT_FILE_LINE9_FMT "offset: %" PRIu64

/*
 * A fragment describes a piece of the shared virtual address space,
 * and is allocated only when allocation is done with the _ODP_ISHM_SINGLE_VA
 * flag:
 * A fragment is said to be used when it actually does represent some
 * portion of the virtual address space, and is said to be unused when
 * it does not (so at start, one single fragment is used -describing the
 * whole address space as unallocated-, and all others are unused).
 * Fragments get used as address space fragmentation increases.
 * A fragment is allocated if the piece of address space it
 * describes is actually used by a shared memory block.
 * Allocated fragments get their block_index set >=0.
 */
typedef struct ishm_fragment {
	struct ishm_fragment *prev; /* not used when the fragment is unused */
	struct ishm_fragment *next;
	void *start;		/* start of segment (VA) */
	uintptr_t   len;	/* length of segment. multiple of page size */
	int   block_index;	/* -1 for unallocated fragments */
} ishm_fragment_t;

/*
 * A block describes a piece of reserved memory: Any successful ishm_reserve()
 * will allocate a block. A ishm_reserve() with the _ODP_ISHM_SINGLE_VA flag set
 * will allocate both a block and a fragment.
 * Blocks contain only global data common to all processes.
 */
typedef enum {UNKNOWN, HUGE, NORMAL, EXTERNAL, CACHED} huge_flag_t;
typedef struct ishm_block {
	char name[ISHM_NAME_MAXLEN];    /* name for the ishm block (if any) */
	char filename[ISHM_FILENAME_MAXLEN]; /* name of the .../odp-* file  */
	char exptname[ISHM_FILENAME_MAXLEN]; /* name of the export file     */
	uint32_t user_flags;     /* any flags the user want to remember.    */
	uint32_t flags;          /* block creation flags.                   */
	uint32_t external_fd:1;  /* block FD was externally provided        */
	uint64_t user_len;	 /* length, as requested at reserve time.   */
	uint64_t offset;	 /* offset from beginning of the fd */
	void *start;		 /* only valid if _ODP_ISHM_SINGLE_VA is set*/
	uint64_t len;		 /* length. multiple of page size. 0 if free*/
	ishm_fragment_t *fragment; /* used when _ODP_ISHM_SINGLE_VA is used */
	huge_flag_t huge;	 /* page type: external means unknown here. */
	uint64_t seq;	/* sequence number, incremented on alloc and free   */
	uint64_t refcnt;/* number of linux processes mapping this block     */
} ishm_block_t;

/*
 * Table of blocks describing allocated internal shared memory
 * This table is visible to every ODP thread (linux process or pthreads).
 * (it is allocated shared at odp init time and is therefore inherited by all)
 * Table index is used as handle, so it cannot move!. Entry is regarded as
 * free when len==0
 */
typedef struct {
	odp_spinlock_t  lock;
	uint64_t dev_seq;	/* used when creating device names */
	/* limit for reserving memory using huge pages */
	uint64_t huge_page_limit;
	uint32_t odpthread_cnt;	/* number of running ODP threads   */
	ishm_block_t  block[ISHM_MAX_NB_BLOCKS];
	void *single_va_start;	/* start of single VA memory */
	int single_va_fd;	/* single VA memory file descriptor */
	odp_bool_t single_va_huge; /* single VA memory from huge pages */
	char single_va_filename[ISHM_FILENAME_MAXLEN];
} ishm_table_t;
static ishm_table_t *ishm_tbl;

/*
 * Process local table containing the list of (believed) allocated blocks seen
 * from the current process. There is one such table per linux process. linux
 * threads within a process shares this table.
 * The contents within this table may become obsolete when other processes
 * reserve/free ishm blocks. This is what the procsync() function
 * catches by comparing the block sequence number with the one in this table.
 * This table is filled at ishm_reserve and ishm_lookup time.
 * Entries are removed at ishm_free or procsync time.
 * Note that flags and len are present in this table and seems to be redundant
 * with those present in the ishm block table: but this is not fully true:
 * When ishm_sync() detects obsolete mappings and tries to remove them,
 * the entry in the ishm block table is then obsolete, and the values which are
 * found in this table must be used to perform the ummap.
 * (and the values in the block tables are needed at lookup time...)
 */
typedef struct {
	int thrd_refcnt; /* number of pthreads in this process, really */
	struct {
		int   block_index; /* entry in the ishm_tbl       */
		uint32_t flags;	   /* flags used at creation time */
		uint64_t seq;
		void *start;  /* start of block (VA)			      */
		uint64_t len; /* length of block. multiple of page size	      */
		int fd;	      /* file descriptor used for this block	      */
	} entry[ISHM_MAX_NB_BLOCKS];
	int nb_entries;
} ishm_proctable_t;
static ishm_proctable_t *ishm_proctable;

/*
 * Table of fragments describing the common virtual address space:
 * This table is visible to every ODP thread (linux process or pthreads).
 * (it is allocated at odp init time and is therefore inherited by all)
 */
typedef struct {
	ishm_fragment_t  fragment[ISHM_NB_FRAGMNTS];
	ishm_fragment_t  *used_fragmnts; /* ordered by increasing start addr */
	ishm_fragment_t  *unused_fragmnts;
} ishm_ftable_t;
static ishm_ftable_t *ishm_ftbl;

struct huge_page_cache {
	uint64_t len;
	int max_fds; /* maximum amount requested of pre-allocated huge pages */
	int total;   /* amount of actually pre-allocated huge pages */
	int idx;     /* retrieve fd[idx] to get a free file descriptor */
	int fd[];    /* list of file descriptors */
};

static struct huge_page_cache *hpc;

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* prototypes: */
static void procsync(void);

static int hp_create_file(uint64_t len, const char *filename)
{
	int fd;
	int ret;
	void *addr;

	if (len <= 0) {
		ODP_ERR("Length is wrong\n");
		return -1;
	}

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		ODP_ERR("Could not create cache file %s\n", filename);
		return -1;
	}

	/* remove file from file system */
	unlink(filename);

	ret = fallocate(fd, 0, 0, len);
	if (ret == -1) {
		if (errno == ENOTSUP) {
			ODP_DBG("fallocate() not supported\n");
			ret = ftruncate(fd, len);
		}

		if (ret == -1) {
			ODP_ERR("memory allocation failed: fd=%d, err=%s.\n",
				fd, strerror(errno));
			close(fd);
			return -1;
		}
	}

	/* commit huge page */
	addr = _odp_ishmphy_map(fd, len, 0, 0);
	if (addr == NULL) {
		/* no more pages available */
		close(fd);
		return -1;
	}
	_odp_ishmphy_unmap(addr, len, 0);

	ODP_DBG("Created HP cache file %s, fd: %d\n", filename, fd);

	return fd;
}

static void hp_init(void)
{
	char filename[ISHM_FILENAME_MAXLEN];
	char dir[ISHM_FILENAME_MAXLEN];
	int count;
	void *addr;

	if (!_odp_libconfig_lookup_ext_int("shm", NULL, "num_cached_hp",
					   &count)) {
		return;
	}

	if (count <= 0)
		return;

	ODP_DBG("Init HP cache with up to %d pages\n", count);

	if (!odp_global_ro.hugepage_info.default_huge_page_dir) {
		ODP_ERR("No huge page dir\n");
		return;
	}

	snprintf(dir, ISHM_FILENAME_MAXLEN, "%s/%s",
		 odp_global_ro.hugepage_info.default_huge_page_dir,
		 odp_global_ro.uid);

	if (mkdir(dir, 0744) != 0) {
		if (errno != EEXIST) {
			ODP_ERR("Failed to create dir: %s\n", strerror(errno));
			return;
		}
	}

	snprintf(filename, ISHM_FILENAME_MAXLEN,
		 "%s/odp-%d-ishm_cached",
		 dir,
		 odp_global_ro.main_pid);

	addr = mmap(NULL,
		    sizeof(struct huge_page_cache) + sizeof(int) * count,
		    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		ODP_ERR("Unable to mmap memory for huge page cache\n.");
		return;
	}

	hpc = addr;

	hpc->max_fds = count;
	hpc->total = 0;
	hpc->idx = -1;
	hpc->len = odp_sys_huge_page_size();

	for (int i = 0; i < count; ++i) {
		int fd;

		fd = hp_create_file(hpc->len, filename);
		if (fd == -1) {
			do {
				hpc->fd[i++] = -1;
			} while (i < count);
			break;
		}
		hpc->total++;
		hpc->fd[i] = fd;
	}
	hpc->idx = hpc->total - 1;

	ODP_DBG("HP cache has %d huge pages of size 0x%08" PRIx64 "\n",
		hpc->total, hpc->len);
}

static void hp_term(void)
{
	if (NULL == hpc)
		return;

	for (int i = 0; i < hpc->total; i++) {
		if (hpc->fd[i] != -1)
			close(hpc->fd[i]);
	}

	hpc->total = 0;
	hpc->idx = -1;
	hpc->len = 0;
}

static int hp_get_cached(uint64_t len)
{
	int fd;

	if (NULL == hpc || hpc->idx < 0 || len != hpc->len)
		return -1;

	fd = hpc->fd[hpc->idx];
	hpc->fd[hpc->idx--] = -1;

	return fd;
}

static int hp_put_cached(int fd)
{
	if (NULL == hpc || odp_unlikely(++hpc->idx >= hpc->total)) {
		hpc->idx--;
		ODP_ERR("Trying to put more FD than allowed: %d\n", fd);
		return -1;
	}

	hpc->fd[hpc->idx] = fd;

	return 0;
}

/*
 * Take a piece of the preallocated virtual space to fit "size" bytes.
 * (best fit). Size must be rounded up to an integer number of pages size.
 * Possibly split the fragment to keep track of remaining space.
 * Returns the allocated fragment (best_fragment) and the corresponding address.
 * External caller must ensure mutex before the call!
 */
static void *alloc_fragment(uintptr_t size, int block_index, intptr_t align,
			    ishm_fragment_t **best_fragmnt)
{
	ishm_fragment_t *fragmnt;
	*best_fragmnt = NULL;
	ishm_fragment_t *rem_fragmnt;
	uintptr_t border;/* possible start of new fragment (next alignement)  */
	intptr_t left;	 /* room remaining after, if the segment is allocated */
	uintptr_t remainder = odp_global_ro.shm_max_memory;

	/*
	 * search for the best bit, i.e. search for the unallocated fragment
	 * would give less remainder if the new fragment was allocated within
	 * it:
	 */
	for (fragmnt = ishm_ftbl->used_fragmnts;
	     fragmnt; fragmnt = fragmnt->next) {
		/* skip allocated segment: */
		if (fragmnt->block_index >= 0)
			continue;
		/* skip too short segment: */
		border = ((uintptr_t)fragmnt->start + align - 1) & (-align);
		left =
		   ((uintptr_t)fragmnt->start + fragmnt->len) - (border + size);
		if (left < 0)
			continue;
		/* remember best fit: */
		if ((uintptr_t)left < remainder) {
			remainder = left; /* best, so far */
			*best_fragmnt = fragmnt;
		}
	}

	if (!(*best_fragmnt)) {
		ODP_ERR("Out of single VA memory. Try increasing "
			"'shm.single_va_size_kb' in ODP config.\n");
		return NULL;
	}

	(*best_fragmnt)->block_index = block_index;
	border = ((uintptr_t)(*best_fragmnt)->start + align - 1) & (-align);

	/*
	 * if there is room between previous fragment and new one, (due to
	 * alignment requirement) then fragment (split) the space between
	 * the end of the previous fragment and the beginning of the new one:
	 */
	if (border - (uintptr_t)(*best_fragmnt)->start > 0) {
		/* fragment space, i.e. take a new fragment descriptor... */
		rem_fragmnt = ishm_ftbl->unused_fragmnts;
		if (!rem_fragmnt) {
			ODP_ERR("unable to get shmem fragment descriptor!\n.");
			return NULL;
		}
		ishm_ftbl->unused_fragmnts = rem_fragmnt->next;

		/* and link it between best_fragmnt->prev and best_fragmnt */
		if ((*best_fragmnt)->prev)
			(*best_fragmnt)->prev->next = rem_fragmnt;
		else
			ishm_ftbl->used_fragmnts = rem_fragmnt;
		rem_fragmnt->prev = (*best_fragmnt)->prev;
		(*best_fragmnt)->prev = rem_fragmnt;
		rem_fragmnt->next = (*best_fragmnt);

		/* update length: rem_fragmnt getting space before border */
		rem_fragmnt->block_index = -1;
		rem_fragmnt->start = (*best_fragmnt)->start;
		rem_fragmnt->len = border - (uintptr_t)(*best_fragmnt)->start;
		(*best_fragmnt)->start =
		     (void *)((uintptr_t)rem_fragmnt->start + rem_fragmnt->len);
		(*best_fragmnt)->len -= rem_fragmnt->len;
	}

	/* if this was a perfect fit, i.e. no free space follows, we are done */
	if (remainder == 0)
		return (*best_fragmnt)->start;

	/* otherwise, fragment space, i.e. take a new fragment descriptor... */
	rem_fragmnt = ishm_ftbl->unused_fragmnts;
	if (!rem_fragmnt) {
		ODP_ERR("unable to get shmem fragment descriptor!\n.");
		return (*best_fragmnt)->start;
	}
	ishm_ftbl->unused_fragmnts = rem_fragmnt->next;

	/* ... double link it... */
	rem_fragmnt->next = (*best_fragmnt)->next;
	rem_fragmnt->prev = (*best_fragmnt);
	if ((*best_fragmnt)->next)
		(*best_fragmnt)->next->prev = rem_fragmnt;
	(*best_fragmnt)->next = rem_fragmnt;

	/* ... and keep track of the remainder */
	(*best_fragmnt)->len = size;
	rem_fragmnt->len = remainder;
	rem_fragmnt->start = (void *)((char *)(*best_fragmnt)->start + size);
	rem_fragmnt->block_index = -1;

	return (*best_fragmnt)->start;
}

/*
 * Free a portion of virtual space.
 * Possibly defragment, if the freed fragment is adjacent to another
 * free virtual fragment.
 * External caller must ensure mutex before the call!
 */
static void free_fragment(ishm_fragment_t *fragmnt)
{
	ishm_fragment_t *prev_f;
	ishm_fragment_t *next_f;

	/* sanity check */
	if (!fragmnt)
		return;

	prev_f = fragmnt->prev;
	next_f = fragmnt->next;

	/* free the fragment */
	fragmnt->block_index = -1;

	/* check if the previous fragment is also free: if so, defragment */
	if (prev_f && (prev_f->block_index < 0)) {
		fragmnt->start = prev_f->start;
		fragmnt->len += prev_f->len;
		if (prev_f->prev) {
			prev_f->prev->next = fragmnt;
		} else {
			if (ishm_ftbl->used_fragmnts == prev_f)
				ishm_ftbl->used_fragmnts = fragmnt;
			else
				ODP_ERR("corrupted fragment list!.\n");
		}
		fragmnt->prev = prev_f->prev;

		/* put removed fragment in free list */
		prev_f->prev = NULL;
		prev_f->next = ishm_ftbl->unused_fragmnts;
		ishm_ftbl->unused_fragmnts = prev_f;
	}

	/* check if the next fragment is also free: if so, defragment */
	if (next_f && (next_f->block_index < 0)) {
		fragmnt->len += next_f->len;
		if (next_f->next)
			next_f->next->prev = fragmnt;
		fragmnt->next = next_f->next;

		/* put removed fragment in free list */
		next_f->prev = NULL;
		next_f->next = ishm_ftbl->unused_fragmnts;
		ishm_ftbl->unused_fragmnts = next_f;
	}
}

static char *create_seq_string(char *output, size_t size)
{
	snprintf(output, size, "%08" PRIu64, ishm_tbl->dev_seq++);

	return output;
}

static int create_export_file(ishm_block_t *new_block, const char *name,
			      uint64_t len, uint32_t flags, uint32_t align,
			      odp_bool_t single_va, uint64_t offset)
{
	FILE *export_file;

	snprintf(new_block->exptname, ISHM_FILENAME_MAXLEN,
		 ISHM_EXPTNAME_FORMAT,
		 odp_global_ro.shm_dir,
		 odp_global_ro.uid,
		 odp_global_ro.main_pid,
		 name);
	export_file = fopen(new_block->exptname, "w");
	if (export_file == NULL) {
		ODP_ERR("open failed: err=%s.\n",
			strerror(errno));
		new_block->exptname[0] = 0;
		return -1;
	}

	fprintf(export_file, EXPORT_FILE_LINE1_FMT "\n");
	fprintf(export_file, EXPORT_FILE_LINE2_FMT "\n",  new_block->name);
	if (single_va)
		fprintf(export_file, EXPORT_FILE_LINE3_FMT "\n",
			ishm_tbl->single_va_filename);
	else
		fprintf(export_file, EXPORT_FILE_LINE3_FMT "\n",
			new_block->filename);

	fprintf(export_file, EXPORT_FILE_LINE4_FMT "\n", len);
	fprintf(export_file, EXPORT_FILE_LINE5_FMT "\n", flags);
	fprintf(export_file, EXPORT_FILE_LINE6_FMT "\n",
		new_block->user_len);
	fprintf(export_file, EXPORT_FILE_LINE7_FMT "\n",
		new_block->user_flags);
	fprintf(export_file, EXPORT_FILE_LINE8_FMT "\n", align);
	fprintf(export_file, EXPORT_FILE_LINE9_FMT "\n", offset);

	fclose(export_file);

	return 0;
}

/*
 * Create file with size len. returns -1 on error
 * Creates a file to /dev/shm/odp-<pid>-<sequence_or_name> (for normal pages)
 * or /mnt/huge/odp-<pid>-<sequence_or_name> (for huge pages).
 * Return the new file descriptor, or -1 on error.
 */
static int create_file(int block_index, huge_flag_t huge, uint64_t len,
		       uint32_t flags, uint32_t align, odp_bool_t single_va)
{
	char *name;
	int  fd;
	ishm_block_t *new_block = NULL;	/* entry in the main block table    */
	char seq_string[ISHM_FILENAME_MAXLEN];   /* used to construct filename*/
	char filename[ISHM_FILENAME_MAXLEN]; /* filename in /dev/shm or
					      *		    /mnt/huge */
	int  oflag = O_RDWR | O_CREAT | O_TRUNC; /* flags for open	      */
	char dir[ISHM_FILENAME_MAXLEN];
	int ret;

	/* No ishm_block_t for the master single VA memory file */
	if (single_va) {
		name = (char *)(uintptr_t)"single_va";
	} else {
		new_block = &ishm_tbl->block[block_index];
		name = new_block->name;
		if (!name || !name[0])
			name = create_seq_string(seq_string,
						 ISHM_FILENAME_MAXLEN);
	}

	/* huge dir must be known to create files there!: */
	if ((huge == HUGE) &&
	    (!odp_global_ro.hugepage_info.default_huge_page_dir))
		return -1;

	if (huge == HUGE)
		snprintf(dir, ISHM_FILENAME_MAXLEN, "%s/%s",
			 odp_global_ro.hugepage_info.default_huge_page_dir,
			 odp_global_ro.uid);
	else
		snprintf(dir, ISHM_FILENAME_MAXLEN, "%s/%s",
			 odp_global_ro.shm_dir,
			 odp_global_ro.uid);

	snprintf(filename, ISHM_FILENAME_MAXLEN, ISHM_FILENAME_FORMAT, dir,
		 odp_global_ro.main_pid, name);

	mkdir(dir, 0744);

	fd = open(filename, oflag, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		if (huge != HUGE)
			ODP_ERR("open failed for %s: %s.\n",
				filename, strerror(errno));
		return -1;
	}

	ret = fallocate(fd, 0, 0, len);
	if (ret == -1) {
		if (errno == ENOTSUP) {
			ODP_DBG("fallocate() not supported\n");
			ret = ftruncate(fd, len);
		}

		if (ret == -1) {
			ODP_ERR("memory allocation failed: fd=%d, err=%s.\n",
				fd, strerror(errno));
			close(fd);
			unlink(filename);
			return -1;
		}
	}

	/* No export file is created since this is only for internal use.*/
	if (single_va) {
		snprintf(ishm_tbl->single_va_filename, ISHM_FILENAME_MAXLEN,
			 "%s", filename);
		return fd;
	}

	/* if _ODP_ISHM_EXPORT is set, create a description file for
	 * external ref:
	 */
	if (flags & _ODP_ISHM_EXPORT) {
		memcpy(new_block->filename, filename, ISHM_FILENAME_MAXLEN);

		create_export_file(new_block, name, len, flags, align, false,
				   0);
	} else {
		new_block->exptname[0] = 0;
		/* remove the file from the filesystem, keeping its fd open */
		unlink(filename);
	}

	return fd;
}

/* delete the files related to a given ishm block: */
static void delete_file(ishm_block_t *block)
{
	/* remove the .../odp-* file, unless fd was external or single va */
	if (block->filename[0] != 0 &&
	    strcmp(block->filename, ishm_tbl->single_va_filename))
		unlink(block->filename);
	/* also remove possible description file (if block was exported): */
	if (block->exptname[0] != 0)
		unlink(block->exptname);
}

/*
 * Performs the mapping.
 * Sets fd, and returns the mapping address. Not to be used with
 * _ODP_ISHM_SINGLE_VA blocks.
 * Mutex must be assured by the caller.
 */
static void *do_map(int block_index, uint64_t len, uint32_t align,
		    uint64_t offset, uint32_t flags, huge_flag_t huge, int *fd)
{
	ishm_block_t *new_block;	  /* entry in the main block table   */
	void *mapped_addr;

	ODP_ASSERT(!(flags & _ODP_ISHM_SINGLE_VA));

	new_block = &ishm_tbl->block[block_index];

	/*
	 * Creates a file to /dev/shm/odp-<pid>-<sequence> (for normal pages)
	 * or /mnt/huge/odp-<pid>-<sequence> (for huge pages)
	 * unless a fd was already given
	 */
	if (*fd < 0) {
		*fd = create_file(block_index, huge, len, flags, align, false);
		if (*fd < 0)
			return NULL;
	} else {
		new_block->filename[0] = 0;
	}

	/* try to mmap: */
	mapped_addr = _odp_ishmphy_map(*fd, len, offset, flags);
	if (mapped_addr == NULL) {
		if (!new_block->external_fd) {
			close(*fd);
			*fd = -1;
			delete_file(new_block);
		}
		return NULL;
	}

	return mapped_addr;
}

/*
 * Allocate block from pre-reserved single VA memory
 */
static void *alloc_single_va(const char *name, int new_index, uint64_t size,
			     uint32_t align, uint32_t flags, int *fd,
			     uint64_t *len_out)
{
	uint64_t len;
	uint64_t page_sz;
	char *file_name = (char *)(uintptr_t)name;
	void *addr;
	ishm_block_t *new_block = &ishm_tbl->block[new_index];
	ishm_fragment_t *fragment = NULL;
	char seq_string[ISHM_FILENAME_MAXLEN];

	if (!file_name || !file_name[0])
		file_name = create_seq_string(seq_string, ISHM_FILENAME_MAXLEN);

	/* Common fd for all single VA blocks */
	*fd = ishm_tbl->single_va_fd;

	if (ishm_tbl->single_va_huge) {
		page_sz = odp_sys_huge_page_size();
		new_block->huge = HUGE;
	} else {
		page_sz = odp_sys_page_size();
		new_block->huge = NORMAL;
	}
	new_block->filename[0] = 0;

	len = (size + (page_sz - 1)) & (-page_sz);

	if (align < page_sz)
		align = page_sz;

	/* Allocate memory from the pre-reserved single VA space */
	addr = alloc_fragment(len, new_index, align, &fragment);
	if (!addr) {
		ODP_ERR("alloc_fragment failed.\n");
		return NULL;
	}
	new_block->fragment = fragment;

	/* Create export info file */
	if (flags & _ODP_ISHM_EXPORT) {
		uint64_t offset = (uintptr_t)addr -
				  (uintptr_t)ishm_tbl->single_va_start;
		memcpy(new_block->filename, ishm_tbl->single_va_filename,
		       ISHM_FILENAME_MAXLEN);

		create_export_file(new_block, file_name, len, flags, align,
				   true, offset);
	} else {
		new_block->exptname[0] = 0;
	}

	*len_out = len;
	return addr;
}

/*
 * Performs an extra mapping (for a process trying to see an existing block
 * i.e. performing a lookup). Not to be used with _ODP_ISHM_SINGLE_VA blocks.
 * Mutex must be assured by the caller.
 */
static void *do_remap(int block_index, int fd)
{
	void *mapped_addr;
	uint64_t len;
	uint64_t offset;
	uint32_t flags;

	len   = ishm_tbl->block[block_index].len;
	offset = ishm_tbl->block[block_index].offset;
	flags = ishm_tbl->block[block_index].flags;

	ODP_ASSERT(!(flags & _ODP_ISHM_SINGLE_VA));

	/* try to mmap: */
	mapped_addr = _odp_ishmphy_map(fd, len, offset, flags);

	if (mapped_addr == NULL)
		return NULL;

	return mapped_addr;
}

/*
 * Performs unmapping, possibly freeing a pre-reserved single VA memory
 * fragment, if the _ODP_ISHM_SINGLE_VA flag was set at alloc time.
 * Mutex must be assured by the caller.
 */
static int do_unmap(void *start, uint64_t size, uint32_t flags,
		    int block_index)
{
	int ret;

	if (start)
		ret = _odp_ishmphy_unmap(start, size, flags);
	else
		ret = 0;

	if ((block_index >= 0) && (flags & _ODP_ISHM_SINGLE_VA)) {
		/* mark reserved address space as free */
		free_fragment(ishm_tbl->block[block_index].fragment);
	}

	return ret;
}

/*
 * Search for a given used and allocated block name.
 * (search is performed in the global ishm table)
 * Returns the index of the found block (if any) or -1 if none.
 * Mutex must be assured by the caller.
 */
static int find_block_by_name(const char *name)
{
	int i;

	if (name == NULL || name[0] == 0)
		return -1;

	for (i = 0; i < ISHM_MAX_NB_BLOCKS; i++) {
		if ((ishm_tbl->block[i].len) &&
		    (strcmp(name, ishm_tbl->block[i].name) == 0))
			return i;
	}

	return -1;
}

/*
 * Search a given ishm block in the process local table. Return its index
 * in the process table or -1 if not found (meaning that the ishm table
 * block index was not referenced in the process local table, i.e. the
 * block is known by some other process, but not by the current process).
 * Caller must assure mutex.
 */
static int procfind_block(int block_index)
{
	int i;

	for (i = 0; i < ishm_proctable->nb_entries; i++) {
		if (ishm_proctable->entry[i].block_index == block_index)
			return i;
	}
	return -1;
}

/*
 * Release the physical memory mapping for blocks which have been freed
 * by other processes. Caller must ensure mutex.
 * Mutex must be assured by the caller.
 */
static void procsync(void)
{
	int i = 0;
	int last;
	ishm_block_t *block;

	last = ishm_proctable->nb_entries;
	while (i < last) {
		/* if the process sequence number doesn't match the main
		 * table seq number, this entry is obsolete
		 */
		block = &ishm_tbl->block[ishm_proctable->entry[i].block_index];
		if (ishm_proctable->entry[i].seq != block->seq) {
			/* obsolete entry: free memory and remove proc entry */
			if (ishm_proctable->entry[i].fd !=
			    ishm_tbl->single_va_fd)
				close(ishm_proctable->entry[i].fd);
			_odp_ishmphy_unmap(ishm_proctable->entry[i].start,
					   ishm_proctable->entry[i].len,
					   ishm_proctable->entry[i].flags);
			ishm_proctable->entry[i] =
			ishm_proctable->entry[--last];
		} else {
			i++;
		}
	}
	ishm_proctable->nb_entries = last;
}

/*
 * Free a block as described in block_free(), but
 * considering whether to close the file descriptor or not, and
 * whether to deregister from the fdserver.
 */
static int block_free_internal(int block_index, int close_fd, int deregister)
{
	int proc_index;
	ishm_block_t *block;	      /* entry in the main block table*/
	int last;
	int ret = 0;

	if ((block_index < 0) ||
	    (block_index >= ISHM_MAX_NB_BLOCKS) ||
	    (ishm_tbl->block[block_index].len == 0)) {
		ODP_ERR("Request to free an invalid block\n");
		return -1;
	}

	block = &ishm_tbl->block[block_index];

	proc_index = procfind_block(block_index);
	if (proc_index >= 0) {
		int fd = ishm_proctable->entry[proc_index].fd;

		/* remove the mapping and possible fragment */
		do_unmap(ishm_proctable->entry[proc_index].start,
			 block->len,
			 ishm_proctable->entry[proc_index].flags,
			 block_index);

		/* close the related fd */
		if (close_fd && (fd != ishm_tbl->single_va_fd)) {
			if (block->huge == CACHED)
				hp_put_cached(fd);
			else
				close(fd);
		}

		/* remove entry from process local table: */
		last = ishm_proctable->nb_entries - 1;
		ishm_proctable->entry[proc_index] = ishm_proctable->entry[last];
		ishm_proctable->nb_entries = last;
	} else {
		/* just possibly free the fragment as no mapping exist here: */
		do_unmap(NULL, 0, block->flags, block_index);
	}

	/* remove all files related to this block: */
	if (close_fd)
		delete_file(block);

	/* deregister the file descriptor from the file descriptor server. */
	if (deregister)
		ret = _odp_fdserver_deregister_fd(FD_SRV_CTX_ISHM, block_index);

	/* mark the block as free in the main block table: */
	block->len = 0;

	/* mark the change so other processes see this entry as obsolete: */
	block->seq++;

	return ret;
}

/*
 * Allocate and map internal shared memory, or other objects:
 * If a name is given, check that this name is not already in use.
 * If ok, allocate a new shared memory block and map the
 * provided fd in it (if fd >=0 was given).
 * If no fd is provided, a shared memory file desc named
 * /dev/shm/odp-<pid>-ishm-<name_or_sequence> is created and mapped.
 * (the name is different for huge page file as they must be on hugepagefs)
 * The function returns the index of the newly created block in the
 * main block table (>=0) or -1 on error.
 */
int _odp_ishm_reserve(const char *name, uint64_t size, int fd,
		      uint32_t align, uint64_t offset,  uint32_t flags,
		      uint32_t user_flags)
{
	int new_index;			      /* index in the main block table*/
	ishm_block_t *new_block;	      /* entry in the main block table*/
	uint64_t page_sz;		      /* normal page size. usually 4K*/
	uint64_t page_hp_size;		      /* huge page size */
	uint32_t hp_align;
	uint64_t len = 0;		      /* mapped length */
	void *addr = NULL;		      /* mapping address */
	int new_proc_entry;
	static int  huge_error_printed;       /* to avoid millions of error...*/

	odp_spinlock_lock(&ishm_tbl->lock);

	/* update this process view... */
	procsync();

	/* Get system page sizes: page_hp_size is 0 if no huge page available*/
	page_sz      = odp_sys_page_size();
	page_hp_size = odp_sys_huge_page_size();

	/* grab a new entry: */
	for (new_index = 0; new_index < ISHM_MAX_NB_BLOCKS; new_index++) {
		if (ishm_tbl->block[new_index].len == 0) {
			/* Found free block */
			break;
		}
	}

	/* check if we have reached the maximum number of allocation: */
	if (new_index >= ISHM_MAX_NB_BLOCKS) {
		odp_spinlock_unlock(&ishm_tbl->lock);
		ODP_ERR("ISHM_MAX_NB_BLOCKS limit reached!\n");
		return -1;
	}

	new_block = &ishm_tbl->block[new_index];

	/* save block name (if any given): */
	if (name)
		strncpy(new_block->name, name, ISHM_NAME_MAXLEN - 1);
	else
		new_block->name[0] = 0;

	new_block->offset = 0;

	/* save user data: */
	new_block->user_flags = user_flags;
	new_block->user_len = size;

	/* If a file descriptor is provided, get the real size and map: */
	if (fd >= 0) {
		new_block->external_fd = 1;
		len = size;
		/* note that the huge page flag is meaningless here as huge
		 * page is determined by the provided file descriptor: */
		addr = do_map(new_index, len, align, offset, flags, EXTERNAL,
			      &fd);
		if (addr == NULL) {
			odp_spinlock_unlock(&ishm_tbl->lock);
			ODP_ERR("_ishm_reserve failed.\n");
			return -1;
		}
		new_block->huge = EXTERNAL;
	} else {
		new_block->external_fd = 0;
		new_block->huge = UNKNOWN;
	}

	/* Otherwise, Try first huge pages when possible and needed: */
	if ((fd < 0) && page_hp_size && ((user_flags &  ODP_SHM_HP) ||
					 size > ishm_tbl->huge_page_limit)) {
		/* at least, alignment in VA should match page size, but user
		 * can request more: If the user requirement exceeds the page
		 * size then we have to make sure the block will be mapped at
		 * the same address every where, otherwise alignment may be
		 * be wrong for some process */
		hp_align = align;
		if (hp_align <= page_hp_size)
			hp_align = page_hp_size;
		else
			flags |= _ODP_ISHM_SINGLE_VA;

		if (flags & _ODP_ISHM_SINGLE_VA)
			goto use_single_va;

		/* roundup to page size */
		len = (size + (page_hp_size - 1)) & (-page_hp_size);

		/* try pre-allocated pages */
		fd = hp_get_cached(len);
		if (fd != -1) {
			/* do as if user provided a fd */
			new_block->external_fd = 1;
			addr = do_map(new_index, len, hp_align, 0, flags,
				      CACHED, &fd);
			if (addr == NULL) {
				ODP_ERR("Could not use cached hp %d\n",
					fd);
				hp_put_cached(fd);
				fd = -1;
			} else {
				new_block->huge = CACHED;
			}
		}
		if (fd == -1) {
			addr = do_map(new_index, len, hp_align, 0, flags, HUGE,
				      &fd);

			if (addr == NULL) {
				if (!huge_error_printed) {
					ODP_ERR("No huge pages, fall back to "
						"normal pages. Check: "
						"/proc/sys/vm/nr_hugepages.\n");
					huge_error_printed = 1;
				}
			} else {
				new_block->huge = HUGE;
			}
		}
	}

	/* Try normal pages if huge pages failed */
	if (fd < 0) {
		if (user_flags & ODP_SHM_HP) {
			odp_spinlock_unlock(&ishm_tbl->lock);
			ODP_ERR("Unable to allocate memory from huge pages\n");
			return -1;
		}
		/* at least, alignment in VA should match page size, but user
		 * can request more: If the user requirement exceeds the page
		 * size then we have to make sure the block will be mapped at
		 * the same address every where, otherwise alignment may be
		 * be wrong for some process */
		if (align <= odp_sys_page_size())
			align = odp_sys_page_size();
		else
			flags |= _ODP_ISHM_SINGLE_VA;

		if (flags & _ODP_ISHM_SINGLE_VA)
			goto use_single_va;

		/* roundup to page size */
		len = (size + (page_sz - 1)) & (-page_sz);
		addr = do_map(new_index, len, align, 0, flags, NORMAL, &fd);
		new_block->huge = NORMAL;
	}

use_single_va:
	/* Reserve memory from single VA space */
	if (fd < 0 && (flags & _ODP_ISHM_SINGLE_VA))
		addr = alloc_single_va(name, new_index, size, align, flags, &fd,
				       &len);

	/* if neither huge pages or normal pages works, we cannot proceed: */
	if ((fd < 0) || (addr == NULL) || (len == 0)) {
		if (new_block->external_fd) {
			if (new_block->huge == CACHED)
				hp_put_cached(fd);
		} else if (fd >= 0 && (fd != ishm_tbl->single_va_fd)) {
			close(fd);
		}
		delete_file(new_block);
		odp_spinlock_unlock(&ishm_tbl->lock);
		ODP_ERR("_ishm_reserve failed.\n");
		return -1;
	}

	/* remember block data and increment block seq number to mark change */
	new_block->len = len;
	new_block->user_len = size;
	new_block->flags = flags;
	new_block->user_flags = user_flags;
	new_block->seq++;
	new_block->refcnt = 1;
	new_block->start = addr; /* only for SINGLE_VA*/

	/* the allocation succeeded: update the process local view */
	new_proc_entry = ishm_proctable->nb_entries++;
	ishm_proctable->entry[new_proc_entry].block_index = new_index;
	ishm_proctable->entry[new_proc_entry].flags = flags;
	ishm_proctable->entry[new_proc_entry].seq = new_block->seq;
	ishm_proctable->entry[new_proc_entry].start = addr;
	ishm_proctable->entry[new_proc_entry].len = len;
	ishm_proctable->entry[new_proc_entry].fd = fd;

	/* register the file descriptor to the file descriptor server. */
	if (_odp_fdserver_register_fd(FD_SRV_CTX_ISHM, new_index, fd) == -1) {
		block_free_internal(new_index, !new_block->external_fd, 0);
		new_index = -1;
	}

	odp_spinlock_unlock(&ishm_tbl->lock);
	return new_index;
}

/*
 * Pre-reserve all single VA memory. Called only in global init.
 */
static void *reserve_single_va(uint64_t size, int *fd_out)
{
	uint64_t page_sz;	/* normal page size. usually 4K*/
	uint64_t page_hp_size;	/* huge page size */
	uint64_t len;		/* mapped length */
	int fd = -1;
	void *addr = NULL;

	/* Get system page sizes: page_hp_size is 0 if no huge page available*/
	page_sz      = odp_sys_page_size();
	page_hp_size = odp_sys_huge_page_size();

	/* Try first huge pages when possible and needed: */
	if (page_hp_size && (size > page_sz)) {
		/* roundup to page size */
		len = (size + (page_hp_size - 1)) & (-page_hp_size);
		fd = create_file(-1, HUGE, len, 0, 0, true);
		if (fd >= 0) {
			addr = _odp_ishmphy_reserve_single_va(len, fd);
			if (!addr) {
				close(fd);
				unlink(ishm_tbl->single_va_filename);
				fd = -1;
			}
		}
		if (fd < 0)
			ODP_ERR("No huge pages, fall back to normal pages. "
				"Check: /proc/sys/vm/nr_hugepages.\n");
		ishm_tbl->single_va_huge = true;
	}

	/* Fall back to normal pages if necessary */
	if (fd < 0) {
		/* roundup to page size */
		len = (size + (page_sz - 1)) & (-page_sz);

		fd = create_file(-1, NORMAL, len, 0, 0, true);
		if (fd >= 0)
			addr = _odp_ishmphy_reserve_single_va(len, fd);
		ishm_tbl->single_va_huge = false;
	}

	/* If neither huge pages or normal pages works, we cannot proceed: */
	if ((fd < 0) || (len == 0) || !addr) {
		if (fd >= 0) {
			close(fd);
			unlink(ishm_tbl->single_va_filename);
		}
		ODP_ERR("Reserving single VA memory failed.\n");
		return NULL;
	}

	*fd_out = fd;
	return addr;
}

/*
 * Try to map an memory block mapped by another ODP instance into the
 * current ODP instance.
 * returns 0 on success.
 */
int _odp_ishm_find_exported(const char *remote_name, pid_t external_odp_pid,
			    const char *local_name)
{
	char export_filename[ISHM_FILENAME_MAXLEN];
	char blockname[ISHM_FILENAME_MAXLEN];
	char filename[ISHM_FILENAME_MAXLEN];
	FILE *export_file;
	uint64_t len;
	uint32_t flags;
	uint64_t user_len;
	uint64_t offset;
	uint32_t user_flags;
	uint32_t align;
	int fd;
	int block_index;

	/* try to read the block description file: */
	snprintf(export_filename, ISHM_FILENAME_MAXLEN,
		 ISHM_EXPTNAME_FORMAT,
		 odp_global_ro.shm_dir,
		 odp_global_ro.uid,
		 external_odp_pid,
		 remote_name);

	export_file = fopen(export_filename, "r");

	if (export_file == NULL) {
		ODP_ERR("Error opening %s.\n", export_filename);
		return -1;
	}

	if (fscanf(export_file, EXPORT_FILE_LINE1_FMT " ") != 0)
		goto error_exp_file;

	if (fscanf(export_file, EXPORT_FILE_LINE2_FMT " ", blockname) != 1)
		goto error_exp_file;

	if (fscanf(export_file, EXPORT_FILE_LINE3_FMT " ", filename) != 1)
		goto error_exp_file;

	if (fscanf(export_file, EXPORT_FILE_LINE4_FMT " ", &len) != 1)
		goto error_exp_file;

	if (fscanf(export_file, EXPORT_FILE_LINE5_FMT " ", &flags) != 1)
		goto error_exp_file;

	if (fscanf(export_file, EXPORT_FILE_LINE6_FMT " ", &user_len) != 1)
		goto error_exp_file;

	if (fscanf(export_file, EXPORT_FILE_LINE7_FMT " ", &user_flags) != 1)
		goto error_exp_file;

	if (fscanf(export_file, EXPORT_FILE_LINE8_FMT " ", &align) != 1)
		goto error_exp_file;

	if (fscanf(export_file, EXPORT_FILE_LINE9_FMT " ", &offset) != 1)
		goto error_exp_file;

	fclose(export_file);

	/* now open the filename given in the description file: */
	fd = open(filename, O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1) {
		ODP_ERR("open failed for %s: %s.\n",
			filename, strerror(errno));
		return -1;
	}

	/* Clear the _ODP_ISHM_EXPORT flag so we don't export again. Single
	 * VA doesn't hold up after export. */
	flags &= ~(uint32_t)_ODP_ISHM_EXPORT;
	flags &= ~(uint32_t)_ODP_ISHM_SINGLE_VA;

	/* reserve the memory, providing the opened file descriptor: */
	block_index = _odp_ishm_reserve(local_name, len, fd, align, offset,
					flags, 0);
	if (block_index < 0) {
		close(fd);
		return block_index;
	}

	/* Offset is required to remap the block to other processes */
	ishm_tbl->block[block_index].offset = offset;

	/* set inherited info: */
	ishm_tbl->block[block_index].user_flags = user_flags;
	ishm_tbl->block[block_index].user_len = user_len;

	return block_index;

error_exp_file:
	fclose(export_file);
	ODP_ERR("Error reading %s.\n", export_filename);
	return -1;
}

/*
 * Free and unmap internal shared memory:
 * The file descriptor is closed and the .../odp-* file deleted,
 * unless fd was externally provided at reserve() time.
 * return 0 if OK, and -1 on error.
 * Mutex must be assured by the caller.
 */
static int block_free(int block_index)
{
	return block_free_internal(block_index, 1, 1);
}

/*
 * Free and unmap internal shared memory, identified by its block number:
 * return -1 on error. 0 if OK.
 */
int _odp_ishm_free_by_index(int block_index)
{
	int ret;

	odp_spinlock_lock(&ishm_tbl->lock);
	procsync();

	ret = block_free(block_index);
	odp_spinlock_unlock(&ishm_tbl->lock);
	return ret;
}

/*
 * Lookup for an ishm shared memory, identified by its block index
 * in the main ishm block table.
 * Map this ishm area in the process VA (if not already present).
 * Returns the block user address or NULL on error.
 * Mutex must be assured by the caller.
 */
static void *block_lookup(int block_index)
{
	int proc_index;
	int fd = -1;
	ishm_block_t *block;
	void *mapped_addr;
	int new_entry;

	if ((block_index < 0) ||
	    (block_index >= ISHM_MAX_NB_BLOCKS) ||
	    (ishm_tbl->block[block_index].len == 0)) {
		ODP_ERR("Request to lookup an invalid block\n");
		return NULL;
	}

	/* search it in process table: if there, this process knows it already*/
	proc_index = procfind_block(block_index);
	if (proc_index >= 0)
		return ishm_proctable->entry[proc_index].start;

	/* this ishm is not known by this process, yet: we create the mapping.*/
	fd = _odp_fdserver_lookup_fd(FD_SRV_CTX_ISHM, block_index);
	if (fd < 0) {
		ODP_ERR("Could not find ishm file descriptor (BUG!)\n");
		return NULL;
	}

	/* perform the mapping */
	block = &ishm_tbl->block[block_index];

	/* No need to remap single VA */
	if (block->flags & _ODP_ISHM_SINGLE_VA)
		mapped_addr = block->start;
	else
		mapped_addr = do_remap(block_index, fd);

	if (mapped_addr == NULL) {
		ODP_ERR(" lookup: Could not map existing shared memory!\n");
		return NULL;
	}

	/* the mapping succeeded: update the process local view */
	new_entry = ishm_proctable->nb_entries++;
	ishm_proctable->entry[new_entry].block_index  = block_index;
	ishm_proctable->entry[new_entry].flags	      = block->flags;
	ishm_proctable->entry[new_entry].seq	      = block->seq;
	ishm_proctable->entry[new_entry].start	      = mapped_addr;
	ishm_proctable->entry[new_entry].len	      = block->len;
	ishm_proctable->entry[new_entry].fd	      = fd;
	block->refcnt++;

	return mapped_addr;
}

/*
 * Lookup for an ishm shared memory, identified by its block name.
 * Return the block index, or -1  if the index does not match any known ishm
 * blocks.
 */
int _odp_ishm_lookup_by_name(const char *name)
{
	int block_index;

	odp_spinlock_lock(&ishm_tbl->lock);
	procsync();

	/* search the block in main ishm table: return -1 if not found: */
	block_index = find_block_by_name(name);

	odp_spinlock_unlock(&ishm_tbl->lock);
	return block_index;
}

/*
 * Returns the VA address of a given block. Maps this ishm area in the process
 * VA (if not already present).
 * Returns NULL if the block is unknown.
 */
void *_odp_ishm_address(int block_index)
{
	void *addr;

	odp_spinlock_lock(&ishm_tbl->lock);
	procsync();

	addr = block_lookup(block_index);

	odp_spinlock_unlock(&ishm_tbl->lock);
	return addr;
}

int _odp_ishm_info(int block_index, _odp_ishm_info_t *info)
{
	int proc_index;

	odp_spinlock_lock(&ishm_tbl->lock);
	procsync();

	if ((block_index < 0) ||
	    (block_index >= ISHM_MAX_NB_BLOCKS) ||
	    (ishm_tbl->block[block_index].len == 0)) {
		odp_spinlock_unlock(&ishm_tbl->lock);
		ODP_ERR("Request for info on an invalid block\n");
		return -1;
	}

	/* search it in process table: if not there, need to map*/
	proc_index = procfind_block(block_index);
	if (proc_index < 0) {
		odp_spinlock_unlock(&ishm_tbl->lock);
		return -1;
	}

	info->name	 = ishm_tbl->block[block_index].name;
	info->addr	 = ishm_proctable->entry[proc_index].start;
	info->size	 = ishm_tbl->block[block_index].user_len;
	info->page_size  = (ishm_tbl->block[block_index].huge == HUGE) ?
			   odp_sys_huge_page_size() : odp_sys_page_size();
	info->flags	 = ishm_tbl->block[block_index].flags;
	info->user_flags = ishm_tbl->block[block_index].user_flags;

	odp_spinlock_unlock(&ishm_tbl->lock);
	return 0;
}

static int do_odp_ishm_init_local(void)
{
	int i;
	int block_index;

	/*
	 * the ishm_process table is local to each linux process
	 * Check that no other linux threads (of same or ancestor processes)
	 * have already created the table, and create it if needed.
	 * We protect this with the general ishm lock to avoid
	 * init race condition of different running threads.
	 */
	odp_spinlock_lock(&ishm_tbl->lock);
	ishm_tbl->odpthread_cnt++; /* count ODPthread (pthread or process) */
	if (!ishm_proctable) {
		ishm_proctable = malloc(sizeof(ishm_proctable_t));
		if (!ishm_proctable) {
			odp_spinlock_unlock(&ishm_tbl->lock);
			return -1;
		}
		memset(ishm_proctable, 0, sizeof(ishm_proctable_t));
	}
	if (syscall(SYS_gettid) != getpid())
		ishm_proctable->thrd_refcnt++;	/* new linux thread  */
	else
		ishm_proctable->thrd_refcnt = 1;/* new linux process */

	/*
	 * if this ODP thread is actually a new linux process, (as opposed
	 * to a pthread), i.e, we just forked, then all shmem blocks
	 * of the parent process are mapped into this child by inheritance.
	 * (The process local table is inherited as well). We hence have to
	 * increase the process refcount for each of the inherited mappings:
	 */
	if (syscall(SYS_gettid) == getpid()) {
		for (i = 0; i < ishm_proctable->nb_entries; i++) {
			block_index = ishm_proctable->entry[i].block_index;
			ishm_tbl->block[block_index].refcnt++;
		}
	}

	odp_spinlock_unlock(&ishm_tbl->lock);
	return 0;
}

/* remove all files staring with "odp-<pid>" from a directory "dir" */
int _odp_ishm_cleanup_files(const char *dirpath)
{
	struct dirent *e;
	DIR *dir;
	char userdir[PATH_MAX];
	char prefix[PATH_MAX];
	char *fullpath;
	int d_len = strlen(dirpath);
	int p_len;
	int f_len;

	snprintf(userdir, PATH_MAX, "%s/%s", dirpath, odp_global_ro.uid);

	dir = opendir(userdir);
	if (!dir) {
		/* ok if the dir does not exist. no much to delete then! */
		ODP_DBG("opendir failed for %s: %s\n",
			dirpath, strerror(errno));
		return 0;
	}
	snprintf(prefix, PATH_MAX, _ODP_FILES_FMT, odp_global_ro.main_pid);
	p_len = strlen(prefix);
	while ((e = readdir(dir)) != NULL) {
		if (strncmp(e->d_name, prefix, p_len) == 0) {
			f_len = strlen(e->d_name);
			fullpath = malloc(d_len + f_len + 2);
			if (fullpath == NULL) {
				closedir(dir);
				return -1;
			}
			snprintf(fullpath, PATH_MAX, "%s/%s",
				 dirpath, e->d_name);
			ODP_DBG("deleting obsolete file: %s\n", fullpath);
			if (unlink(fullpath))
				ODP_ERR("unlink failed for %s: %s\n",
					fullpath, strerror(errno));
			free(fullpath);
		}
	}
	closedir(dir);

	return 0;
}

int _odp_ishm_init_global(const odp_init_t *init)
{
	void *addr;
	void *spce_addr = NULL;
	int i;
	int val_kb;
	uid_t uid;
	char *hp_dir = odp_global_ro.hugepage_info.default_huge_page_dir;
	uint64_t max_memory;
	uint64_t internal;
	uint64_t huge_page_limit;

	if (!_odp_libconfig_lookup_ext_int("shm", NULL, "single_va_size_kb",
					   &val_kb)) {
		ODP_ERR("Unable to read single VA size from config\n");
		return -1;
	}

	ODP_DBG("Shm single VA size: %dkB\n", val_kb);

	max_memory = (uint64_t)val_kb * 1024;
	internal   = max_memory / 8;

	if (!_odp_libconfig_lookup_ext_int("shm", NULL, "huge_page_limit_kb",
					   &val_kb)) {
		ODP_ERR("Unable to read huge page usage limit from config\n");
		return -1;
	}
	huge_page_limit = (uint64_t)val_kb * 1024;

	ODP_DBG("Shm huge page usage limit: %dkB\n", val_kb);

	/* user requested memory size + some extra for internal use */
	if (init && init->shm.max_memory)
		max_memory = init->shm.max_memory + internal;

	odp_global_ro.shm_max_memory = max_memory;
	odp_global_ro.shm_max_size   = max_memory - internal;
	odp_global_ro.main_pid = getpid();
	odp_global_ro.shm_dir = getenv("ODP_SHM_DIR");
	if (odp_global_ro.shm_dir) {
		odp_global_ro.shm_dir_from_env = 1;
	} else {
		odp_global_ro.shm_dir =
			calloc(1, sizeof(ISHM_FILENAME_NORMAL_PAGE_DIR));
		sprintf(odp_global_ro.shm_dir, "%s",
			ISHM_FILENAME_NORMAL_PAGE_DIR);
		odp_global_ro.shm_dir_from_env = 0;
	}

	ODP_DBG("ishm: using dir %s\n", odp_global_ro.shm_dir);

	uid = getuid();
	snprintf(odp_global_ro.uid, UID_MAXLEN, "%d",
		 uid);

	if ((syscall(SYS_gettid)) != odp_global_ro.main_pid) {
		ODP_ERR("ishm init must be performed by the main "
			"ODP process!\n.");
		return -1;
	}

	if (!hp_dir) {
		ODP_DBG("NOTE: No support for huge pages\n");
	} else {
		ODP_DBG("Huge pages mount point is: %s\n", hp_dir);
		_odp_ishm_cleanup_files(hp_dir);
	}

	_odp_ishm_cleanup_files(odp_global_ro.shm_dir);

	/* allocate space for the internal shared mem block table: */
	addr = mmap(NULL, sizeof(ishm_table_t),
		    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		ODP_ERR("unable to mmap the main block table\n.");
		goto init_glob_err1;
	}
	ishm_tbl = addr;
	memset(ishm_tbl, 0, sizeof(ishm_table_t));
	ishm_tbl->dev_seq = 0;
	ishm_tbl->odpthread_cnt = 0;
	ishm_tbl->huge_page_limit = huge_page_limit;
	odp_spinlock_init(&ishm_tbl->lock);

	/* allocate space for the internal shared mem fragment table: */
	addr = mmap(NULL, sizeof(ishm_ftable_t),
		    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		ODP_ERR("unable to mmap the main fragment table\n.");
		goto init_glob_err2;
	}
	ishm_ftbl = addr;
	memset(ishm_ftbl, 0, sizeof(ishm_ftable_t));

	/* Reserve memory for _ODP_ISHM_SINGLE_VA reserved blocks */
	ishm_tbl->single_va_fd = -1;
	if (max_memory) {
		spce_addr = reserve_single_va(max_memory,
					      &ishm_tbl->single_va_fd);
		if (!spce_addr) {
			ODP_ERR("unable to reserve single VA memory\n.");
			goto init_glob_err3;
		}
		ishm_tbl->single_va_start = spce_addr;
	}

	/* use the first fragment descriptor to describe to whole VA space: */
	ishm_ftbl->fragment[0].block_index   = -1;
	ishm_ftbl->fragment[0].start = spce_addr;
	ishm_ftbl->fragment[0].len   = max_memory;
	ishm_ftbl->fragment[0].prev  = NULL;
	ishm_ftbl->fragment[0].next  = NULL;
	ishm_ftbl->used_fragmnts   = &ishm_ftbl->fragment[0];

	/* and put all other fragment descriptors in the unused list: */
	for (i = 1; i < ISHM_NB_FRAGMNTS - 1; i++) {
		ishm_ftbl->fragment[i].prev   = NULL;
		ishm_ftbl->fragment[i].next   = &ishm_ftbl->fragment[i + 1];
	}
	ishm_ftbl->fragment[ISHM_NB_FRAGMNTS - 1].prev   = NULL;
	ishm_ftbl->fragment[ISHM_NB_FRAGMNTS - 1].next   = NULL;
	ishm_ftbl->unused_fragmnts = &ishm_ftbl->fragment[1];

	/*
	 * We run _odp_ishm_init_local() directely here to give the
	 * possibility to run shm_reserve() before the odp_init_local()
	 * is performed for the main thread... Many init_global() functions
	 * indeed assume the availability of odp_shm_reserve()...:
	 */
	if (do_odp_ishm_init_local()) {
		ODP_ERR("unable to init the main thread\n.");
		goto init_glob_err4;
	}

	/* get ready to create pools: */
	_odp_ishm_pool_init();

	/* init cache files */
	hp_init();

	return 0;

init_glob_err4:
	if (_odp_ishmphy_free_single_va())
		ODP_ERR("unable to free single VA memory\n.");
init_glob_err3:
	if (munmap(ishm_ftbl, sizeof(ishm_ftable_t)) < 0)
		ODP_ERR("unable to munmap main fragment table\n.");
init_glob_err2:
	if (munmap(ishm_tbl, sizeof(ishm_table_t)) < 0)
		ODP_ERR("unable to munmap main block table\n.");
init_glob_err1:
	return -1;
}

int _odp_ishm_init_local(void)
{
	/*
	 * Do not re-run this for the main ODP process, as it has already
	 * been done in advance at _odp_ishm_init_global() time:
	 */
	if ((getpid() == odp_global_ro.main_pid) &&
	    (syscall(SYS_gettid) == getpid()))
		return 0;

	return do_odp_ishm_init_local();
}

static int do_odp_ishm_term_local(void)
{
	int i;
	int proc_table_refcnt = 0;
	int block_index;
	ishm_block_t *block;

	procsync();

	ishm_tbl->odpthread_cnt--; /* decount ODPthread (pthread or process) */

	/*
	 * The ishm_process table is local to each linux process
	 * Check that no other linux threads (of this linux process)
	 * still needs the table, and free it if so.
	 * We protect this with the general ishm lock to avoid
	 * term race condition of different running threads.
	 */
	proc_table_refcnt = --ishm_proctable->thrd_refcnt;
	if (!proc_table_refcnt) {
		/*
		 * this is the last thread of this process...
		 * All mappings for this process are about to be lost...
		 * Go through the table of visible blocks for this process,
		 * decreasing the refcnt of each visible blocks, and issuing
		 * warning for those no longer referenced by any process.
		 * Note that non-referenced blocks are not freed: this is
		 * deliberate as this would imply that the semantic of the
		 * freeing function would differ depending on whether we run
		 * with odp_thread as processes or pthreads. With this approach,
		 * the user should always free the blocks manually, which is
		 * more consistent
		 */
		for (i = 0; i < ishm_proctable->nb_entries; i++) {
			block_index = ishm_proctable->entry[i].block_index;
			block = &ishm_tbl->block[block_index];
			if ((--block->refcnt) <= 0) {
				block->refcnt = 0;
			ODP_DBG("Warning: block %d:  name:%s "
				"no longer referenced\n",
				i,
				ishm_tbl->block[i].name[0] ?
					ishm_tbl->block[i].name : "<no name>");
			}
		}

		free(ishm_proctable);
		ishm_proctable = NULL;
	}

	return 0;
}

int _odp_ishm_term_local(void)
{
	int ret;

	odp_spinlock_lock(&ishm_tbl->lock);

	/* postpone last thread term to allow free() by global term functions:*/
	if (ishm_tbl->odpthread_cnt == 1) {
		odp_spinlock_unlock(&ishm_tbl->lock);
		return 0;
	}

	ret = do_odp_ishm_term_local();
	odp_spinlock_unlock(&ishm_tbl->lock);
	return ret;
}

int _odp_ishm_term_global(void)
{
	int ret = 0;
	int index;
	int fd = ishm_tbl->single_va_fd;
	ishm_block_t *block;

	if ((getpid() != odp_global_ro.main_pid) ||
	    (syscall(SYS_gettid) != getpid()))
		ODP_ERR("odp_term_global() must be performed by the main "
			"ODP process!\n.");

	/* cleanup possibly non freed memory (and complain a bit): */
	for (index = 0; index < ISHM_MAX_NB_BLOCKS; index++) {
		block = &ishm_tbl->block[index];
		if (block->len != 0) {
			ODP_ERR("block '%s' (file %s) was never freed "
				"(cleaning up...).\n",
				block->name, block->filename);
			delete_file(block);
		}
	}

	/* perform the last thread terminate which was postponed: */
	ret = do_odp_ishm_term_local();

	/* remove the file from the filesystem, keeping its fd open */
	unlink(ishm_tbl->single_va_filename);

	/* free the fragment table */
	if (munmap(ishm_ftbl, sizeof(ishm_ftable_t)) < 0) {
		ret |= -1;
		ODP_ERR("unable to munmap fragment table\n.");
	}
	/* free the block table */
	if (munmap(ishm_tbl, sizeof(ishm_table_t)) < 0) {
		ret |= -1;
		ODP_ERR("unable to munmap main table\n.");
	}

	/* free the reserved single VA memory */
	if (_odp_ishmphy_free_single_va())
		ret |= -1;
	if ((fd >= 0) && close(fd)) {
		ret |= -1;
		ODP_ERR("unable to close single VA\n.");
	}

	if (!odp_global_ro.shm_dir_from_env)
		free(odp_global_ro.shm_dir);

	hp_term();

	return ret;
}

/*
 * Print the current ishm status (allocated blocks and VA space map)
 * Return the number of allocated blocks (including those not mapped
 * by the current odp thread). Also perform a number of sanity check.
 * For debug.
 */
int _odp_ishm_status(const char *title)
{
	int i;
	char flags[3];
	char huge;
	int proc_index;
	ishm_fragment_t *fragmnt;
	int consecutive_unallocated = 0; /* should never exceed 1 */
	uintptr_t last_address = 0;
	ishm_fragment_t *previous = NULL;
	int nb_used_frgments = 0;
	int nb_unused_frgments = 0;	/* nb frag describing a VA area */
	int nb_allocated_frgments = 0;	/* nb frag describing an allocated VA */
	int nb_blocks = 0;
	int single_va_blocks = 0;
	int max_name_len = 0;
	uint64_t lost_total = 0; /* statistics for total unused memory */
	uint64_t len_total = 0;  /* statistics for total allocated memory */

	odp_spinlock_lock(&ishm_tbl->lock);
	procsync();

	/* find longest block name */
	for (i = 0; i < ISHM_MAX_NB_BLOCKS; i++) {
		int str_len;

		if (ishm_tbl->block[i].len <= 0)
			continue;

		str_len = strlen(ishm_tbl->block[i].name);

		if (max_name_len < str_len)
			max_name_len = str_len;
	}

	ODP_PRINT("%s\n", title);
	ODP_PRINT("    %-*s flag %-29s %-08s   %-08s %-3s %-3s %-3s file\n",
		  max_name_len, "name", "range", "user_len", "unused",
		  "seq", "ref", "fd");

	/* display block table: 1 line per entry +1 extra line if mapped here */
	for (i = 0; i < ISHM_MAX_NB_BLOCKS; i++) {
		void *start_addr = NULL;
		void *end_addr = NULL;
		int entry_fd = -1;

		if (ishm_tbl->block[i].len <= 0)
			continue; /* unused block */

		nb_blocks++;
		if (ishm_tbl->block[i].flags & _ODP_ISHM_SINGLE_VA)
			single_va_blocks++;

		flags[0] = (ishm_tbl->block[i].flags & _ODP_ISHM_SINGLE_VA) ?
								'S' : '.';
		flags[1] = (ishm_tbl->block[i].flags & _ODP_ISHM_LOCK) ?
								'L' : '.';
		flags[2] = 0;
		switch (ishm_tbl->block[i].huge) {
		case HUGE:
			huge = 'H';
			break;
		case NORMAL:
			huge = 'N';
			break;
		case EXTERNAL:
			huge = 'E';
			break;
		case CACHED:
			huge = 'C';
			break;
		default:
			huge = '?';
		}
		proc_index = procfind_block(i);
		lost_total += ishm_tbl->block[i].len -
			      ishm_tbl->block[i].user_len;
		len_total += ishm_tbl->block[i].len;

		if (proc_index >= 0) {
			start_addr = ishm_proctable->entry[proc_index].start;
			end_addr = (void *)(uintptr_t)((uintptr_t)start_addr +
					ishm_tbl->block[i].len);
			entry_fd = ishm_proctable->entry[proc_index].fd;
		}

		ODP_PRINT("%2i  %-*s %s%c  0x%-08lx-0x%08lx %-08ld   %-08ld %-3lu %-3lu %-3d %s\n",
			  i, max_name_len, ishm_tbl->block[i].name,
			  flags, huge, start_addr, end_addr,
			  ishm_tbl->block[i].user_len,
			  ishm_tbl->block[i].len - ishm_tbl->block[i].user_len,
			  ishm_tbl->block[i].seq,
			  ishm_tbl->block[i].refcnt,
			  entry_fd,
			  ishm_tbl->block[i].filename[0] ?
					  ishm_tbl->block[i].filename :
					  "(none)");
	}
	ODP_PRINT("TOTAL: %58s%-08ld %2s%-08ld\n",
		  "", len_total,
		  "", lost_total);
	ODP_PRINT("%65s(%dMB) %4s(%dMB)\n",
		  "", len_total / 1024 / 1024,
		  "", lost_total / 1024 / 1024);


	/* display the virtual space allocations... : */
	ODP_PRINT("\nishm virtual space:\n");
	for (fragmnt = ishm_ftbl->used_fragmnts;
	     fragmnt; fragmnt = fragmnt->next) {
		if (fragmnt->block_index >= 0) {
			nb_allocated_frgments++;
			ODP_PRINT("  %08p - %08p: ALLOCATED by block:%d\n",
				  (uintptr_t)fragmnt->start,
				  (uintptr_t)fragmnt->start + fragmnt->len - 1,
				  fragmnt->block_index);
			consecutive_unallocated = 0;
		} else {
			ODP_PRINT("  %08p - %08p: NOT ALLOCATED\n",
				  (uintptr_t)fragmnt->start,
				  (uintptr_t)fragmnt->start + fragmnt->len - 1);
			if (consecutive_unallocated++)
				ODP_ERR("defragmentation error\n");
		}

		/* some other sanity checks: */
		if (fragmnt->prev != previous)
				ODP_ERR("chaining error\n");

		if (fragmnt != ishm_ftbl->used_fragmnts) {
			if ((uintptr_t)fragmnt->start != last_address + 1)
				ODP_ERR("lost space error\n");
		}

		last_address = (uintptr_t)fragmnt->start + fragmnt->len - 1;
		previous = fragmnt;
		nb_used_frgments++;
	}

	/*
	 * the number of blocks with the single_VA flag set should match
	 * the number of used fragments:
	 */
	if (single_va_blocks != nb_allocated_frgments)
		ODP_ERR("single_va_blocks != nb_allocated_fragments!\n");

	/* compute the number of unused fragments*/
	for (fragmnt = ishm_ftbl->unused_fragmnts;
	     fragmnt; fragmnt = fragmnt->next)
		nb_unused_frgments++;

	ODP_PRINT("ishm: %d fragment used. %d fragments unused. (total=%d)\n",
		  nb_used_frgments, nb_unused_frgments,
		  nb_used_frgments + nb_unused_frgments);

	if ((nb_used_frgments + nb_unused_frgments) != ISHM_NB_FRAGMNTS)
		ODP_ERR("lost fragments!\n");

	if (nb_blocks < ishm_proctable->nb_entries)
		ODP_ERR("process known block cannot exceed main total sum!\n");

	ODP_PRINT("\n");

	odp_spinlock_unlock(&ishm_tbl->lock);
	return nb_blocks;
}

void _odp_ishm_print(int block_index)
{
	ishm_block_t *block;
	const char *str;

	odp_spinlock_lock(&ishm_tbl->lock);

	if ((block_index < 0) ||
	    (block_index >= ISHM_MAX_NB_BLOCKS) ||
	    (ishm_tbl->block[block_index].len == 0)) {
		odp_spinlock_unlock(&ishm_tbl->lock);
		ODP_ERR("Request for info on an invalid block\n");
		return;
	}

	block = &ishm_tbl->block[block_index];

	ODP_PRINT("\nSHM block info\n--------------\n");
	ODP_PRINT(" name:       %s\n",   block->name);
	ODP_PRINT(" file:       %s\n",   block->filename);
	ODP_PRINT(" expt:       %s\n",   block->exptname);
	ODP_PRINT(" user_flags: 0x%x\n", block->user_flags);
	ODP_PRINT(" flags:      0x%x\n", block->flags);
	ODP_PRINT(" user_len:   %lu\n",  block->user_len);
	ODP_PRINT(" start:      %p\n",   block->start);
	ODP_PRINT(" len:        %lu\n",  block->len);

	switch (block->huge) {
	case HUGE:
		str = "huge";
		break;
	case NORMAL:
		str = "normal";
		break;
	case EXTERNAL:
		str = "external";
		break;
	case CACHED:
		str = "cached";
		break;
	default:
		str = "??";
	}

	ODP_PRINT(" page type:  %s\n", str);
	ODP_PRINT(" seq:        %lu\n",  block->seq);
	ODP_PRINT(" refcnt:     %lu\n",  block->refcnt);
	ODP_PRINT("\n");

	odp_spinlock_unlock(&ishm_tbl->lock);
}
