/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

/**
 * @file
 *
 * ODP Proto Stats
 */

#ifndef ODP_API_SPEC_PROTO_STATS_H_
#define ODP_API_SPEC_PROTO_STATS_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_proto_stats
 *  @{
 */

/**
 * @def ODP_PROTO_STATS_INVALID
 * Invalid proto stats handle
 */

/** ODP proto stats id */
typedef enum odp_proto_stats_id_t {
	/** None */
	ODP_PROTO_STATS_ID_NONE,
} odp_proto_stats_id_t;

/** ODP proto stats mode */
typedef enum odp_proto_stats_mode_t {
	ODP_PROTO_STATS_MODE_MAX,
} odp_proto_stats_mode_t;

/** ODP proto stats params */
typedef struct odp_proto_stats_param_t {
	/** Mode of the proto stats object */
	odp_proto_stats_mode_t mode;
} odp_proto_stats_param_t;

/**
 * Proto stats capabilities
 */
typedef struct odp_proto_stats_capa_t {
	/** Supported proto stat modes */
	odp_bool_t modes[ODP_PROTO_STATS_MODE_MAX];
} odp_proto_stats_capa_t;

/**
 * Initialize proto stats parameters
 *
 * Initialize an odp_proto_stats_param_t to its default values.
 *
 * @param param   Proto stats parameter pointer.
 */
void odp_proto_stats_init(odp_proto_stats_param_t *param);

/**
 * Get proto stats capability
 *
 * Get proto stats capability of supported modes.
 *
 * @param capa Pointer where capabilities are updated.
 */
void odp_proto_stats_capa(odp_proto_stats_capa_t *capa);

/**
 * Create a proto stats object
 *
 * Create a proto stats object with given name and mode.
 * Semantics of each mode is associated with that mode.
 *
 * @param name  Object name
 * @param param Proto stats parameters
 *
 * @return Proto stats object handle
 */
odp_proto_stats_t odp_proto_stats_create(const char *name, const odp_proto_stats_param_t *param);

/**
 * Lookup a proto stats object by name
 *
 * Lookup an already created proto stats object by name.
 *
 * @param name Proto stats object name
 *
 * @return Proto stats object handle
 */
odp_proto_stats_t odp_proto_stats_lookup(const char *name);

/**
 * Destroy a proto stats object
 *
 * Destroy a proto stats object already created.
 *
 * @param stat Proto stats handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_proto_stats_destroy(odp_proto_stats_t stat);

/**
 * Get proto stats base
 *
 * Get pointer to array of 64-bit elements where stats are updated. Index for the array is based
 * on type of proto stat object and stat id.
 *
 * @param stat      Proto stat object handle
 * @param max_index Pointer to location where max index allowed to base array is returned.
 *
 * @return Pointer to base of stats array
 */
uint64_t *odp_proto_stats(odp_proto_stats_t stat, uint16_t *max_index);

/**
 * Get proto stats array index
 *
 * Get array index of proto stats base for a given proto stats id.
 *
 * @param stat Proto stats object handle
 * @param id   Statistics id.
 *
 * @return Index to proto stats array
 * @retval >=0 on success
 * @retval <0 on failure
 */
int odp_proto_stats_index(odp_proto_stats_t stat, odp_proto_stats_id_t id);

/**
 * Print proto stats object info on console.
 *
 * Print implementation-defined proto stats debug information to the console.
 *
 * @param stat Proto stats object handle
 */
void odp_proto_stats_print(odp_proto_stats_t stat);
/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
