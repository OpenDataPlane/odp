/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string.h>
#include <unistd.h>
#include <odp/api/std_types.h>
#include <odp/api/byteorder.h>
#include <odp_bitmap_internal.h>

/*
 * WAPL base class bitmap operations
 */
static inline void __wapl_add_pos(
	wapl_bitmap_t *map, unsigned int p)
{
	unsigned int s, k = 0;
	unsigned int *pl = map->pl;

	while (pl[k] && p > pl[k])
		k++;

	if (p == pl[k])
		return;

	/* sorted insertion */
	for (; pl[k] && p < pl[k]; k++) {
		s = pl[k];
		pl[k] = p;
		p = s;
	}

	if (k < map->nwords)
		pl[k++] = p;

	pl[k] = 0;
}

static inline void __wapl_remove_pos(
	wapl_bitmap_t *map, unsigned int p)
{
	unsigned int k = 0;
	unsigned int *pl = map->pl;

	while (pl[k] && p != pl[k])
		k++;

	for (; pl[k]; k++)
		pl[k] = pl[k + 1];
}

void __wapl_bitmap_and(wapl_bitmap_t *dst,
		       wapl_bitmap_t *src, wapl_bitmap_t *and)
{
	unsigned int k = 0, p;
	unsigned int *pl = src->pl;

	while ((p = *pl++) != 0) {
		dst->ul[p] = src->ul[p] & and->ul[p];
		if (dst->ul[p])
			dst->pl[k++] = p;
	}

	dst->pl[k] = 0;
}

void __wapl_bitmap_or(wapl_bitmap_t *dst, wapl_bitmap_t *or)
{
	unsigned int p;
	unsigned int *pl = or->pl;

	while ((p = *pl++) != 0) {
		if (dst->ul[p] == 0)
			__wapl_add_pos(dst, p);

		dst->ul[p] |= or->ul[p];
	}
}

void __wapl_bitmap_set(wapl_bitmap_t *map, unsigned int bit)
{
	unsigned int p = BIT_WORD(bit) + 1;
	unsigned long set = 1UL << (bit & (BITS_PER_LONG - 1));

	if (p > map->nwords)
		return;

	if (map->ul[p] == 0)
		__wapl_add_pos(map, p);

	map->ul[p] |= set;
}

void __wapl_bitmap_clear(wapl_bitmap_t *map, unsigned int bit)
{
	unsigned int p = BIT_WORD(bit) + 1;
	unsigned long clear = 1UL << (bit & (BITS_PER_LONG - 1));

	if (p > map->nwords)
		return;

	map->ul[p] &= ~clear;

	if (map->ul[p] == 0)
		__wapl_remove_pos(map, p);
}

/*
 * WAPL bitmap iterator implementation
 */
static void __wapl_iterator_start(wapl_bitmap_iterator_t *this)
{
	this->_nbits = this->_base.nwords * BITS_PER_LONG;

	/* Advance to next queue index to start this
	 * new round iteration.
	 */
	if (this->_base.pl[0] == 0)
		this->_start = -1;
	else
		this->_start = __bitmap_wraparound_next(
			&this->_base.ul[1], this->_nbits, this->_start + 1);

	this->_next = this->_start;
}

static bool __wapl_iterator_has_next(wapl_bitmap_iterator_t *this)
{
	return (this->_next != -1);
}

static unsigned int __wapl_iterator_next(wapl_bitmap_iterator_t *this)
{
	int next = this->_next;

	this->_next = __bitmap_wraparound_next(
			&this->_base.ul[1], this->_nbits, this->_next + 1);

	if (this->_next == this->_start)
		this->_next = -1;

	return next;
}

void __wapl_bitmap_iterator(wapl_bitmap_iterator_t *this)
{
	this->start = __wapl_iterator_start;
	this->has_next = __wapl_iterator_has_next;
	this->next = __wapl_iterator_next;

	this->_start = -1;
	this->_next = this->_start;
}

/*
 * Sparse base class bitmap operations
 */
void __sparse_bitmap_set(sparse_bitmap_t *map, unsigned int bit)
{
	unsigned int last = *map->last;

	/* Index exceeds */
	if (bit >= map->nbits)
		return;

	/* Full bitmap */
	if (last >= map->nbits)
		return;

	/* Bit was not set previously,
	 * also record where we set the bit
	 */
	if (!map->pl[bit]) {
		map->il[last++] = bit;
		map->pl[bit] = last;

		*map->last = last;
	}
}

void __sparse_bitmap_clear(sparse_bitmap_t *map, unsigned int bit)
{
	unsigned int p, i;
	unsigned int last = *map->last;

	/* Index exceeds */
	if (bit >= map->nbits)
		return;

	/* Empty bitmap */
	if (last == 0)
		return;

	/* Bit was set previously */
	if (map->pl[bit]) {
		p = map->pl[bit] - 1;
		map->pl[bit] = 0;

		last--;
		*map->last = last;

		/* Fill the hole with the latest index */
		if (p < last) {
			i = map->il[last];
			map->pl[i] = p + 1;
			map->il[p] = i;
		}
	}
}

/*
 * Sparse bitmap iterator implementation
 */
static void __sparse_iterator_start(sparse_bitmap_iterator_t *this)
{
	this->_nbits = (int)*this->_base.last;

	/* Advance to next queue index to start this
	 * new round iteration.
	 */
	if (this->_nbits == 0)
		this->_start = -1;
	else
		this->_start = (this->_start + 1) & (this->_nbits - 1);

	this->_next = this->_start;
}

static bool __sparse_iterator_has_next(sparse_bitmap_iterator_t *this)
{
	return (this->_next != -1);
}

static unsigned int __sparse_iterator_next(sparse_bitmap_iterator_t *this)
{
	int next = this->_next;

	this->_next = (this->_next + 1) & (this->_nbits - 1);
	if (this->_next == this->_start)
		this->_next = -1;

	return this->_base.il[next];
}

void __sparse_bitmap_iterator(sparse_bitmap_iterator_t *this)
{
	this->start = __sparse_iterator_start;
	this->has_next = __sparse_iterator_has_next;
	this->next = __sparse_iterator_next;

	this->_start = -1;
	this->_next = this->_start;
}

/*
 * Generic byte-width atomic set/clear
 */
static inline void atomic_byte_set(
	unsigned char *addr, unsigned int bit)
{
	unsigned char load, store;
	unsigned char set = 1 << (bit & (BITS_PER_BYTE - 1));

	do {
		load = *addr;
		store = load | set;
	} while (!__atomic_compare_exchange_n(addr, &load, store,
			0, __ATOMIC_RELEASE, __ATOMIC_RELAXED));
}

static inline void atomic_byte_clear(
	unsigned char *addr, unsigned int bit)
{
	unsigned char load, store;
	unsigned char clear = 1 << (bit & (BITS_PER_BYTE - 1));

	do {
		load = *addr;
		store = load & ~clear;
	} while (!__atomic_compare_exchange_n(addr, &load, store,
			0, __ATOMIC_RELEASE, __ATOMIC_RELAXED));
}

static inline unsigned char *__bit_byte(
	unsigned long *word, unsigned int bit)
{
	unsigned int i;
	unsigned char *b;

	b = (unsigned char *)word;

	i = bit & (BITS_PER_LONG - 1);
	i = i / BITS_PER_BYTE;

#if (ODP_BYTE_ORDER == ODP_BIG_ENDIAN)
	i = BYTES_PER_LONG - 1 - i;
#endif
	return &b[i];
}

void raw_bitmap_set(unsigned long *map, unsigned int bit)
{
	unsigned long *p = map + BIT_WORD(bit);

	atomic_byte_set(__bit_byte(p, bit), bit);
}

void raw_bitmap_clear(unsigned long *map, unsigned int bit)
{
	unsigned long *p = map + BIT_WORD(bit);

	atomic_byte_clear(__bit_byte(p, bit), bit);
}
