/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef ODPH_CUCKOO_TABLE_H_
#define ODPH_CUCKOO_TABLE_H_

#include <odp/helper/table.h>

/**
 * @file
 *
 * ODP Cuckoo Hash Table
 */

#ifdef __cplusplus
extern "C" {
#endif

odph_table_t odph_cuckoo_table_create(
		const char *name,
		uint32_t capacity,
		uint32_t key_size,
		uint32_t value_size);

odph_table_t odph_cuckoo_table_lookup(const char *name);

int odph_cuckoo_table_destroy(odph_table_t table);

int odph_cuckoo_table_put_value(
		odph_table_t table,
		void *key, void *value);

int odph_cuckoo_table_get_value(
		odph_table_t table,
		void *key, void *buffer,
		uint32_t buffer_size);

int odph_cuckoo_table_remove_value(odph_table_t table, void *key);

extern odph_table_ops_t odph_cuckoo_table_ops;

#ifdef __cplusplus
}
#endif

#endif /* ODPH_CUCKOO_TABLE_H_ */
