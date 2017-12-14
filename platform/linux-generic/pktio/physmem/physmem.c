/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>

#include <config.h>
#include <odp_align_internal.h>
#include <odp_debug_internal.h>
#include <_ishmphy_internal.h>
#include <pktio/physmem/physmem.h>

#define KB * 1024ULL
#define MB * 1024ULL KB

#define lock_list()
#define unlock_list()

#define HUGEPAGES_PATH "/dev/hugepages/"

#define MAX_HUGEPAGES 128

/* make hugepage_info 128 bytes long */
#define FILENAME_PATH_MAX 96

struct hugepage_info {
	struct physmem_block *block; /* the block this hugepage belongs to */
	void *va; /* virtual address this hugepage is mapped to */
	uint64_t pa; /* the physical address of this hugepage */
	uint32_t size; /* size of hugepage */
	int fd; /* the fd returned by open, for the hugepages file */
	char filename[FILENAME_PATH_MAX];
};

typedef LIST_HEAD(block_list, physmem_block) block_list_t;

struct physmem_block_data {
	struct physmem_block block[MAX_HUGEPAGES];
	block_list_t avail; /* blocks of huge pages ready to use */
	block_list_t used;  /* blocks allocated and being in use */
	block_list_t empty; /* blocks without any hugepages, size 0 */
	uint32_t hp_size;
	uint32_t count;
};

static struct hugepage_info pages[MAX_HUGEPAGES];
static struct physmem_block_data block_data;

static int alloc_hugepage(struct hugepage_info *hp)
{
	static int file_id = 0;
	int len;

	if (hp == NULL)
		return -1;

	len = snprintf(hp->filename, sizeof(hp->filename),
		       HUGEPAGES_PATH "odp-%d", file_id);
	if (len >= FILENAME_PATH_MAX) {
		ODP_ERR("Filename too large (%d)\n", len);
		return -1;
	}

	hp->fd = open(hp->filename, O_CREAT | O_RDWR, 0755);
	if (hp->fd == -1) {
		perror("open");
		return -1;
	}

	hp->va = mmap(NULL, 2 MB, PROT_READ | PROT_WRITE, MAP_SHARED, hp->fd,
		      0);
	if (hp->va == MAP_FAILED) {
		perror("mmap");
		close(hp->fd);
		unlink(hp->filename);
		return -1;
	}

	/* Force memory commitment */
	*((int *)(hp->va)) = hp->fd;

	hp->size = 2 MB; /* FIXME: defaulting to 2MB huge pages */
	hp->pa = _odp_ishmphy_getphy(hp->va);
	if (hp->pa == PHYS_ADDR_INVALID)
		ODP_ERR("Could not discover PA\n"); /* FIXME */

	hp->block = NULL;

	file_id++;

	return 0;
}

static int comp_hp(const void *_a, const void *_b)
{
	const struct hugepage_info *a = _a;
	const struct hugepage_info *b = _b;

	if (a->pa > b->pa)
		return 1;
	else if (a->pa < b->pa)
		return -1;
	else
		return 0;
}

static int init_hugepages(void)
{
	memset(pages, 0, sizeof(pages));

	for (int i = 0; i < MAX_HUGEPAGES; ++i) {
		if (alloc_hugepage(&pages[i]) != 0) {
			ODP_ERR("Could not allocate hugepages\n");
			return -1;
		}
	}

	qsort(pages, MAX_HUGEPAGES, sizeof(pages[0]), comp_hp);

	return 0;
}

static int comp_block(const void *_a, const void *_b)
{
	const struct physmem_block *a = _a;
	const struct physmem_block *b = _b;

	if (a->count > b->count)
		return 1;
	else if (a->count < b->count)
		return -1;
	else
		return 0;
}

/*
 * hp is a SORTED array of count elements of struct hugepage_info,
 * it is sorted per physical address in ascending order.
 * This returns a linked list of struct physmem_block, each block containing
 * a reference to physically contiguous huge pages.
 */
static int sort_in_blocks(struct hugepage_info *hp_array, int count)
{
	uint32_t block_id;
	int hp_id;
	struct physmem_block *block;
	struct hugepage_info *hp;

	if (hp_array == NULL || count == 0)
		return -EINVAL;

	block_id = 0;
	hp_id = 0;
	hp = &hp_array[0];
	do {
		uint64_t pa_expected;

		block = &block_data.block[block_id];
		block->first = hp_id;
		block->size = hp->size;
		block->pa = hp->pa;
		block->va = NULL;
		block->count = 1;
		block->id = block_id++;
		block->hp_size = hp->size;
		block->type = BLOCK_AVAIL;

		block_data.count++;

		ODP_DBG("New block %d\n", block->id);
		ODP_DBG("\t%03d: VA: %016" PRIx64 ", PA: %016" PRIx64 "\n",
			hp->fd, hp->va, hp->pa);

		pa_expected = block->pa + hp->size;

		/* keep adding huge pages to this block as long as their
		 * physical address coincides with the expected one */
		while (++hp_id < count) {
			hp++;

			if (hp->pa != pa_expected)
				break;

			ODP_DBG("\t%03d: VA: %016" PRIx64 ", PA: %016" PRIx64
				"\n", hp->fd, hp->va, hp->pa);

			block->count++;
			block->size += hp->size;

			pa_expected += hp->size;
		}

		ODP_DBG("\tSize: %" PRIu64 " MB\n", (block->size / (1 MB)));
	} while (hp_id < count);

	qsort(block_data.block, block_data.count, sizeof(block_data.block[0]),
	      comp_block);

	/* link sorted blocks together */
	struct physmem_block *last = &block_data.block[0];
	pages[last->first].block = last;
	pages[last->first + last->count - 1].block = last;
	LIST_INSERT_HEAD(&block_data.avail, last, next);
	for (block_id = 1; block_id < block_data.count; ++block_id) {
		block = &block_data.block[block_id];
		pages[block->first].block = block;
		pages[block->first + block->count - 1].block = block;
		LIST_INSERT_AFTER(last, block, next);
		last = block;
	}

	/* insert rest of blocks into the empty list */
	for (block_id = block_data.count; block_id < MAX_HUGEPAGES; ++block_id){
		block = &block_data.block[block_id];
		block->id = block_id;
		block->type = BLOCK_EMPTY;
		LIST_INSERT_HEAD(&block_data.empty, block, next);
	}

	block_data.hp_size = block_data.block[0].hp_size;

	return 0;
}

static struct physmem_block *block_get(void)
{
	struct physmem_block *block;

	if (LIST_EMPTY(&block_data.empty))
		return NULL;

	block = LIST_FIRST(&block_data.empty);
	LIST_REMOVE(block, next);

	return block;
}

struct physmem_block *physmem_block_alloc(uint64_t size)
{
	struct physmem_block *block;
	struct physmem_block *ret = NULL;
	uint32_t num_hp;

	size = ROUNDUP_ALIGN(size, block_data.hp_size);
	num_hp = size / block_data.hp_size;

	lock_list();

	LIST_FOREACH(block, &block_data.avail, next) {
		if (block->count < num_hp)
			continue;
		else if (block->count == num_hp) {
			LIST_REMOVE(block, next);
			ret = block;
			break;
		} else {
			struct hugepage_info *hp;

			ret = block_get();
			if (ret == NULL)
				break;

			/* slice num_hp pages from this block */
			block->count -= num_hp;
			block->size = block->count * block->hp_size;

			ret->first = block->first + block->count;
			ret->count = num_hp;
			ret->hp_size = block->hp_size;
			ret->size = ret->hp_size * num_hp;
			ret->va = NULL;

			/* reassign pages to their corresponding block
			 * only the borders need to be updated */
			hp = &pages[ret->first];
			hp->block = ret;
			ret->pa = hp->pa;
			hp--; /* last page of the block we just sliced */
			hp->block = block;
			hp += num_hp; /* last page of the block we just allocated */
			hp->block = ret;

			/* place the sliced block back into the list at correct position */
			LIST_REMOVE(block, next);

			if (LIST_EMPTY(&block_data.avail)) {
				LIST_INSERT_HEAD(&block_data.avail, block, next);
			} else {
				struct physmem_block *last = NULL;
				struct physmem_block *tmp;

				LIST_FOREACH(tmp, &block_data.avail, next) {
					if (tmp->count >= block->count) {
						LIST_INSERT_BEFORE(tmp, block, next);
						last = NULL;
						break;
					}
					last = tmp;
				}
				if (last)
					LIST_INSERT_AFTER(last, block, next);
			}

			break;
		}
	}

	if (ret != NULL) {
		ret->type = BLOCK_USED;
		LIST_INSERT_HEAD(&block_data.used, ret, next);
	}

	unlock_list();

	return ret;
}

void physmem_block_free(struct physmem_block *block)
{
	if (block == NULL)
		return;

	lock_list();

	LIST_REMOVE(block, next);

	/* append this block to left block if available */
	if (block->first != 0) {
		struct hugepage_info *left_hp, *first_hp;
		struct physmem_block *left_block;
		uint64_t expected_pa;

		first_hp = &pages[block->first];
		left_hp = first_hp - 1;
		left_block = left_hp->block;
		expected_pa = left_hp->pa + left_hp->size;

		if (left_block->type == BLOCK_AVAIL && block->pa == expected_pa) {
			/* put the pages belonging to this block in to the left one */
			left_block->count += block->count;
			left_block->size = left_block->count * left_block->hp_size;

			pages[left_block->first + left_block->count - 1].block = left_block;

			block->size = 0;
			block->pa = 0;
			block->va = 0;
			block->first = 0;
			block->count = 0;
			block->type = BLOCK_EMPTY;
			LIST_INSERT_HEAD(&block_data.empty, block, next);

			block = left_block;
			LIST_REMOVE(block, next);
		}
	}

	/* join with right block if available */
	uint32_t right_idx = block->first + block->count;
	if (right_idx < MAX_HUGEPAGES) {
		struct hugepage_info *last_hp;
		struct hugepage_info *right_hp;
		struct physmem_block *right_block;
		uint64_t expected_pa;

		right_hp = &pages[right_idx];
		last_hp = right_hp - 1;
		right_block = right_hp->block;
		expected_pa = last_hp->pa + last_hp->size;

		if (right_block->type == BLOCK_AVAIL
		    && expected_pa == right_block->pa) {
			block->count += right_block->count;
			block->size = block->count * block->hp_size;

			pages[block->first + block->count - 1].block = block;

			LIST_REMOVE(right_block, next);
			right_block->size = 0;
			right_block->pa = 0;
			right_block->va = 0;
			right_block->first = 0;
			right_block->count = 0;
			right_block->type = BLOCK_EMPTY;
			LIST_INSERT_HEAD(&block_data.empty, right_block, next);
		}
	}

	block->type = BLOCK_AVAIL;
	if (LIST_EMPTY(&block_data.avail)) {
			LIST_INSERT_HEAD(&block_data.avail, block, next);
	} else {
		struct physmem_block *tmp, *last = NULL;

		LIST_FOREACH(tmp, &block_data.avail, next) {
			if (tmp->count >= block->count) {
				LIST_INSERT_BEFORE(tmp, block, next);
				last = NULL;
				break;
			}
			last = tmp;
		}
		if (last != NULL)
			LIST_INSERT_AFTER(last, block, next);
	}

	unlock_list();
}

int physmem_block_map(struct physmem_block *block, void *anchor_addr)
{
	void *addr;
	int retval;
	int mapped_cnt;
	struct hugepage_info *hp;

	if (block == NULL || anchor_addr == NULL)
		return -EINVAL;

	/* make sure we can actually map this memory region */
	addr = mmap(anchor_addr, block->size,
		    PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED,
		    -1, 0);

	if (addr == MAP_FAILED)
		return errno;

	block->va = addr;
	mapped_cnt = 0;

	ODP_DBG("Mapping block %d at %p\n", block->id, block->va);

	for (uint32_t i = 0; i < block->count; ++i) {
		void *tmp;

		hp = &pages[block->first + i];

		if ((hp->va != NULL) && (munmap(hp->va, hp->size) != 0)) {
			ODP_DBG("Error unmapping old va: %p\n", hp->va);
			retval = -EINVAL;
			goto exit_failure;
		}

		if (munmap(addr, hp->size) != 0) {
			retval = errno;
			goto exit_failure;
		}

		tmp = mmap(addr, hp->size,
			   PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_FIXED,
			   hp->fd, 0);
		if (tmp == MAP_FAILED) {
			retval = errno;
			perror("mmap");
			ODP_DBG("Error remapping PA:0x%" PRIu64 " to %p\n",
				hp->pa, tmp);
			goto exit_failure;
		}

		mapped_cnt++;

#ifdef ENABLE_MAP_CHECKS
		/* check: we poison the page with the file descriptor number */
		int fd = *((int *)tmp);
		if (fd != hp->fd) {
			ODP_DBG("Checking expected resulted in mismatch!\n");
			goto exit_failure;
		}

		uint64_t pa = _odp_ishmphy_getphy(tmp);
		if (pa != hp->pa) {
			retval = -EFAULT;
			ODP_DBG("Physical address error, PA orig: "
				"0x%016" PRIx64 "\nPA  new: 0x%016" PRIx64 "\n",
				hp->pa, pa);
			goto exit_failure;
		}
#endif

		ODP_DBG("\t%03d: VA: 0x%016" PRIx64 " -> 0x%016" PRIx64
			", PA: 0x%016" PRIx64 "\n",
			hp->fd, hp->va, tmp, hp->pa);

		hp->va = addr;

		addr = (void *)((char *)addr + hp->size);
	}

	return 0;

exit_failure:

	while (mapped_cnt--) {
		hp = &pages[block->first + mapped_cnt];
		munmap(hp->va, hp->size);
		hp->va = NULL;
	}
	block->va = NULL;

	return retval;
}

int physmem_block_unmap(struct physmem_block *block)
{
	struct hugepage_info *hp;
	int ret = 0;

	if (block == NULL || block->va == NULL)
		return -EINVAL;

	hp = &pages[block->first];
	for (uint32_t i = 0; i < block->count; ++i, ++hp) {
		*((int *)hp->va) = hp->fd;
		if (munmap(hp->va, hp->size))
			ret = errno;
	}

	return ret;
}

static void init_blocks(void)
{
	memset(&block_data, 0, sizeof(block_data));

	LIST_INIT(&block_data.avail);
	LIST_INIT(&block_data.used);
	LIST_INIT(&block_data.empty);
}

int physmem_block_init_global(void)
{
	init_blocks();

	if (init_hugepages())
		return -1;

	if (sort_in_blocks(pages, MAX_HUGEPAGES) != 0)
		return -1;

	return 0;
}

int physmem_block_term_global(void)
{
	for (int i = 0; i < MAX_HUGEPAGES; ++i) {
		if (pages[i].fd == 0)
			continue;
		close(pages[i].fd);
		unlink(pages[i].filename);
	}

	return 0;
}

#if 0
static void zero_block(struct physmem_block *block)
{
	if (block == NULL || block->va == NULL)
		return;

	memset(block->va, 0, block->size);
}

/* this makes sure the VA area is also physically contiguous */
static int check_va_area(const void *va, uint64_t size, uint64_t page_size)
{
	uint64_t pa;
	uint64_t expected_pa;
	uint64_t offset;

	pa = _odp_ishmphy_getphy(va);
	if (pa == PHYS_ADDR_INVALID)
		return -1;
	ODP_PRINT("VA: %p -> PA: %016" PRIx64 "\n", va, pa);

	expected_pa = pa + page_size;
	offset = page_size;
	while (offset < size) {
		va = (const void *)((const char *)va + offset);
		pa = _odp_ishmphy_getphy(va);

		if (pa == PHYS_ADDR_INVALID)
			return -1;

		ODP_PRINT("VA: %p -> PA: %016" PRIx64 "\n", va, pa);

		if (pa != expected_pa) {
			ODP_ERR("ERRROR: not expected PA %016" PRIx64 "...\n",
				expected_pa);
			return -1;
		}

		expected_pa += page_size;
	}

	return 0;
}
#endif

int physmem_block_check(const struct physmem_block *block)
{
	struct hugepage_info *first, *last;
	int ret = 0;

	first = &pages[block->first];
	last = &pages[block->first + block->count - 1];
	if (first->block != block) {
		ret = 1;
		ODP_ERR("\tfirst block does not match, got %u\n",
			first->block->id);
	}
	if (last->block != block) {
		ret = 1;
		ODP_ERR("\tlast block does not match, got %u\n",
			last->block->id);
	}
	return ret;
}

static void print_pages(struct physmem_block *block)
{
	for (uint32_t i = 0; i < block->count; ++i) {
		struct hugepage_info *hp = &pages[block->first + i];
		ODP_PRINT("\t%03d: VA: 0x%p PA: 0x%016" PRIx64 "\n",
			  hp->fd, hp->va, hp->pa);
	}
}

static void print_block_list(block_list_t *list, int pages)
{
	struct physmem_block *block;

	LIST_FOREACH(block, list, next) {
		ODP_PRINT("Block %" PRIu32 "\n", block->id);
		ODP_PRINT("\tSize: %" PRIu64 " MB\n", block->size / (1 MB));
		ODP_PRINT("\tVA start: 0x%016" PRIx64 "\n", block->va);
		ODP_PRINT("\tPA start: 0x%016" PRIx64 "\n", block->pa);
		ODP_PRINT("\tHP start: %u-%u\n",
			  block->first, block->first + block->count - 1);
		ODP_PRINT("\tcount: %u hugepages\n", block->count);
		if (pages)
			print_pages(block);
	}
}

void physmem_block_dump(physmem_block_type_t type, int pages)
{
	const char *type_str;
	block_list_t *list;

	switch (type) {
	case BLOCK_EMPTY:
		type_str = "EMPTY\n";
		list = &block_data.empty;
		break;
	case BLOCK_AVAIL:
		type_str = "AVAIL\n";
		list = &block_data.avail;
		break;
	case BLOCK_USED:
		type_str = "USED\n";
		list = &block_data.used;
		break;
	default:
		return;
	}

	ODP_PRINT(type_str);

	print_block_list(list, pages);
}
