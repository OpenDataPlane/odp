/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP Linear Table
 */

#ifndef ODPH_LINEAR_TABLE_H_
#define ODPH_LINEAR_TABLE_H_

#include <stdint.h>
#include <odp/helper/table.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup odph_lineartable ODPH LINEAR TABLE
 * Linear table
 *
 * @{
 */

/**
 * Create a linear table
 *
 * @param name        Name of the linear table to be created
 * @param capacity    Number of elements table may store
 * @param ODP_IGNORED Ignored parameter
 * @param value_size  Size of the value stored for each element
 *
 * @return Handle of created linear table
 * @return NULL Create failed
 */
odph_table_t odph_linear_table_create(const char *name,
				      uint32_t capacity,
				      uint32_t ODP_IGNORED,
				      uint32_t value_size);

/**
 * Lookup a linear table
 *
 * @param name Name of the table to be located
 *
 * @return Handle of the located linear table
 * @retval NULL No table matching supplied name found
 */
odph_table_t odph_linear_table_lookup(const char *name);

/**
 * Destroy a linear table
 *
 * @param table Handle of linear table to be destroyed
 *
 * @retval 0   Success
 * @retval < 0 Failure
 */
int odph_linear_table_destroy(odph_table_t table);

/**
 * Insert a value into a linear table
 *
 * @param table Table into which value is to be stored
 * @param key   Index value used as key
 * @param value Value to be assoceiated with specified key index
 *
 * @retval >= 0 Success
 * @retval < 0  Failure
 */
int odph_linear_put_value(odph_table_t table, void *key, void *value);

/**
 * Retrieve a value from a linear table
 *
 * @param table Table from which value is to be retrieved
 * @param key   Index value used as key
 * @param[out] buffer Address of buffer to receive resulting value
 * @param buffer_size Size of supplied buffer
 *
 * @retval 0   Success
 * @retval 1   Success
 * @retval < 0 Failure
 */
int odph_linear_get_value(odph_table_t table, void *key, void *buffer,
			  uint32_t buffer_size);

extern odph_table_ops_t odph_linear_table_ops; /**< @internal */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
