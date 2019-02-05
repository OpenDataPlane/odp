/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP generic bitmap types and operations.
 */

#ifndef ODP_BITMAP_INTERNAL_H_
#define ODP_BITMAP_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <odp/api/hints.h>
#include <odp_macros_internal.h>

/* Generate unique identifier for instantiated class */
#define TOKENIZE(template, line) \
	template ## _ ## line ## _ ## __COUNTER__

#define BITS_PER_BYTE	(8)
#define BITS_PER_LONG	__WORDSIZE
#define BYTES_PER_LONG	(BITS_PER_LONG / BITS_PER_BYTE)

#define BIT_WORD(nr)	((nr) / BITS_PER_LONG)
#define BITS_TO_LONGS(nr) BIT_WORD(nr + BITS_PER_LONG - 1)

#define BITMAP_FIRST_WORD_MASK(start) \
	(~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits)  \
	(~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))

/* WAPL bitmap base class */
typedef struct {
	unsigned int  nwords;
	unsigned int  *pl;
	unsigned long *ul;
} wapl_bitmap_t;

/*
 * Word-Aligned Position List (WAPL) bitmap, which actually
 * is not a compression, but with an extra list of non-empty
 * word positions.
 *
 * WAPL accelerates bitwise operations and iterations by
 * applying only to non-empty positions instead of walking
 * through the whole bitmap.
 *
 * WAPL uses [1 ~ N] instead of [0 ~ N - 1] as position
 * values and an extra 0 as end indicator for position list.
 * This is the reason to allocate one extra room below.
 */
#define instantiate_wapl_bitmap(line, nbits)			\
	struct TOKENIZE(wapl_bitmap, line) {			\
		unsigned int pl[BITS_TO_LONGS(nbits) + 1];	\
		unsigned long ul[BITS_TO_LONGS(nbits) + 1];	\
	}

#define WAPL_BITMAP(nbits) instantiate_wapl_bitmap(__LINE__, nbits)

/*
 * Upcast any derived WAPL bitmap class to its base class
 */
#define __wapl_upcast(base, derived)				\
	do {							\
		__typeof__(derived) p = derived;		\
		base.pl = p->pl;				\
		base.ul = p->ul;				\
		base.nwords = ARRAY_SIZE(p->ul) - 1;		\
	} while (0)

/*
 * WAPL base class bitmap operations
 */
void __wapl_bitmap_and(wapl_bitmap_t *dst,
		       wapl_bitmap_t *src, wapl_bitmap_t *and);

void __wapl_bitmap_or(wapl_bitmap_t *dst, wapl_bitmap_t *or);

void __wapl_bitmap_set(wapl_bitmap_t *map, unsigned int bit);

void __wapl_bitmap_clear(wapl_bitmap_t *map, unsigned int bit);

/*
 * Generic WAPL bitmap operations
 */
#define wapl_bitmap_zero(map)					\
	({							\
		__typeof__(map) p = map;			\
		memset((void *)p, 0, sizeof(__typeof__(*p)));	\
	})

#define wapl_bitmap_copy(dst, src)				\
	({							\
		__typeof__(dst) d = dst;			\
		__typeof__(src) s = src;			\
		if (d != s)					\
			memcpy((void *)d, (void *)s,		\
				sizeof(__typeof__(*d)));	\
	})

#define wapl_bitmap_and(dst, src, and)				\
	({							\
		wapl_bitmap_t d, s, a;				\
		__wapl_upcast(d, dst);				\
		__wapl_upcast(s, src);				\
		__wapl_upcast(a, and);				\
		__wapl_bitmap_and(&d, &s, &a);			\
	})

#define wapl_bitmap_or(dst, src, or)				\
	({							\
		wapl_bitmap_t d, o;				\
		wapl_bitmap_copy(dst, src);			\
		__wapl_upcast(d, dst);				\
		__wapl_upcast(o, or);				\
		__wapl_bitmap_or(&d, &o);			\
	})

#define wapl_bitmap_set(map, bit)				\
	({							\
		wapl_bitmap_t b;				\
		__wapl_upcast(b, map);				\
		__wapl_bitmap_set(&b, bit);			\
	})

#define wapl_bitmap_clear(map, bit)				\
	({							\
		wapl_bitmap_t b;				\
		__wapl_upcast(b, map);				\
		__wapl_bitmap_clear(&b, bit);			\
	})

/*
 * Round robin iterator runs upon a WAPL bitmap:
 *
 * wapl_bitmap_iterator(iterator, WAPL bitmap);
 * for (iterator->start(); iterator->has_next(); ) {
 *	unsigned int bit_index = iterator->next();
 *	...operations on this bit index...
 * }
 */
typedef struct wapl_bitmap_iterator {
	int _start, _next, _nbits;
	wapl_bitmap_t _base;

	void (*start)(struct wapl_bitmap_iterator *this);
	bool (*has_next)(struct wapl_bitmap_iterator *this);
	unsigned int (*next)(struct wapl_bitmap_iterator *this);
} wapl_bitmap_iterator_t;

/*
 * WAPL bitmap iterator constructor
 */
void __wapl_bitmap_iterator(wapl_bitmap_iterator_t *this);

/*
 * Generic constructor accepts any derived WAPL bitmap class
 */
#define wapl_bitmap_iterator(iterator, map)			\
	({							\
		__typeof__(iterator) __it = iterator;		\
		__wapl_upcast(__it->_base, map);		\
		__wapl_bitmap_iterator(__it);			\
	})

/* Sparse bitmap base class */
typedef struct {
	unsigned int nbits;
	unsigned int *last, *pl, *il;
} sparse_bitmap_t;

/*
 * Sparse bitmap, lists all bit indexes directly as an array.
 * Expected to be significantly straightforward iteration.
 */
#define instantiate_sparse_bitmap(line, nbits)			\
	struct TOKENIZE(sparse_bitmap, line) {			\
		unsigned int last;				\
		unsigned int pl[nbits];				\
		unsigned int il[nbits];				\
	}

#define SPARSE_BITMAP(nbits) instantiate_sparse_bitmap(__LINE__, nbits)

/*
 * Upcast any derived sparse bitmap class to its base class
 */
#define __sparse_upcast(base, derived)				\
	do {							\
		__typeof__(derived) p = derived;		\
		base.pl = p->pl;				\
		base.il = p->il;				\
		base.last = &p->last;				\
		base.nbits = ARRAY_SIZE(p->il);			\
	} while (0)

/*
 * Sparse base class bitmap operations
 */
void __sparse_bitmap_set(sparse_bitmap_t *map, unsigned int bit);

void __sparse_bitmap_clear(sparse_bitmap_t *map, unsigned int bit);

/*
 * Generic sparse bitmap operations
 */
#define sparse_bitmap_zero(map)					\
	({							\
		__typeof__(map) p = map;			\
		memset((void *)p, 0, sizeof(__typeof__(*p)));	\
	})

#define sparse_bitmap_set(map, bit)				\
	({							\
		sparse_bitmap_t b;				\
		__sparse_upcast(b, map);			\
		__sparse_bitmap_set(&b, bit);			\
	})

#define sparse_bitmap_clear(map, bit)				\
	({							\
		sparse_bitmap_t b;				\
		__sparse_upcast(b, map);			\
		__sparse_bitmap_clear(&b, bit);			\
	})

/*
 * Round robin iterator runs upon a sparse bitmap:
 *
 * sparse_bitmap_iterator(iterator, SPARSE bitmap);
 * for (iterator->start(); iterator->has_next(); ) {
 *	unsigned int bit_index = iterator->next();
 *	...operations on this bit index...
 * }
 */
typedef struct sparse_bitmap_iterator {
	int _start, _next, _nbits;
	sparse_bitmap_t _base;

	void (*start)(struct sparse_bitmap_iterator *this);
	bool (*has_next)(struct sparse_bitmap_iterator *this);
	unsigned int (*next)(struct sparse_bitmap_iterator *this);
} sparse_bitmap_iterator_t;

/*
 * Sparse bitmap iterator constructor
 */
void __sparse_bitmap_iterator(sparse_bitmap_iterator_t *this);

/*
 * Generic constructor accepts any derived sparse bitmap class.
 */
#define sparse_bitmap_iterator(iterator, map)			\
	({							\
		__typeof__(iterator) __it = iterator;		\
		__sparse_upcast(__it->_base, map);		\
		__sparse_bitmap_iterator(__it);			\
	})

/*
 * Raw bitmap atomic set and clear.
 */
void raw_bitmap_set(unsigned long *map, unsigned int bit);

void raw_bitmap_clear(unsigned long *map, unsigned int bit);

/*
 * It will enter infinite loop incase that all bits are zero,
 * so please make sure the bitmap at least has one set.
 */
static inline int __bitmap_wraparound_next(unsigned long *addr,
					   unsigned int nbits, int start)
{
	unsigned long tmp;

	if (start >= (int)nbits)
		start = 0;

	tmp = addr[BIT_WORD(start)];

	/* Handle 1st word. */
	tmp &= BITMAP_FIRST_WORD_MASK(start);
	start = start & ~(BITS_PER_LONG - 1);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= (int)nbits)
			start = 0;

		tmp = addr[BIT_WORD(start)];
	}

	start += __builtin_ffsl(tmp) - 1;
	return start;
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
