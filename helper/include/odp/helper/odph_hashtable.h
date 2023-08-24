/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Hash Table
 */

#ifndef ODPH_HASH_TABLE_H_
#define ODPH_HASH_TABLE_H_

#include <odp/helper/table.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup odph_hash_table ODPH HASH TABLE
 * Hash table
 *
 * @{
 */

/**
 * Create a hash table
 *
 * @param name       Name of the hash table to be created.
 * @param capacity   Number of elements table may store
 * @param key_size   Size of the key for each element
 * @param value_size Size of the value stored for each element
 *
 * @return Handle of created hash table
 * @retval NULL Create failed
 */
odph_table_t odph_hash_table_create(const char *name,
				    uint32_t capacity,
				    uint32_t key_size,
				    uint32_t value_size);

/**
 * Lookup a hash table by name
 *
 * @param name Name of the table to be located
 *
 * @return Handle of the located hash table
 * @return NULL No table matching supplied name found
 */
odph_table_t odph_hash_table_lookup(const char *name);

/**
 * Destroy a hash table
 *
 * @param table Handle of the hash table to be destroyed
 *
 * @retval 0   Success
 * @retval < 0 Failure
 */
int odph_hash_table_destroy(odph_table_t table);

/**
 * Insert a key/value pair into a hash table
 *
 * @param table Table into which value is to be stored
 * @param key   Address of an odph_table_t to be used as key
 * @param value Value to be associated with specified key
 *
 * @retval >= 0 Success
 * @retval < 0  Failure
 */
int odph_hash_put_value(odph_table_t table, void *key, void *value);

/**
 * Retrieve a value from a hash table
 *
 * @param table Table from which value is to be retrieved
 * @param key   Address of an odph_table_t to be used as key
 * @param[out] buffer Address of buffer to receive resulting value
 * @param buffer_size Size of supplied buffer
 *
 * @retval 0   Success
 * @retval 1   Success
 * @retval < 0 Failure
 */
int odph_hash_get_value(odph_table_t table, void *key, void *buffer,
			uint32_t buffer_size);

/**
 * Remove a value from a hash table
 *
 * @param table Table from which value is to be removed
 * @param key   Address of odph_table_t to be used as key
 *
 * @retval >= 0 Success
 * @retval < 0  Failure
 */
int odph_hash_remove_value(odph_table_t table, void *key);

extern odph_table_ops_t odph_hash_table_ops; /**< @internal */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
