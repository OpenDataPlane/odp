/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2019 Nokia
 */

/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_API_ABI_PACKET_H_
#define ODP_API_ABI_PACKET_H_

#include <odp/api/plat/packet_inlines.h>

/*
 * Request the static inline definitions of the deprecated packet vector API.
 * This header is included (before the API prototypes) only in inline builds,
 * where defining the inline functions cannot clash with the prototypes. See
 * packet_vector_inlines.h for details.
 */
#define _ODP_PACKET_VECTOR_ABI_INLINE
#include <odp/api/plat/packet_vector_inlines.h>

#endif
