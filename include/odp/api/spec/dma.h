/* Copyright (c) 2021-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP DMA
 */

#ifndef ODP_API_SPEC_DMA_H_
#define ODP_API_SPEC_DMA_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/dma_types.h>
#include <odp/api/pool_types.h>

/** @addtogroup odp_dma
 *  @{
 */

/**
 * Query DMA capabilities
 *
 * Outputs DMA capabilities on success.
 *
 * @param[out] capa     Pointer to a capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_dma_capability(odp_dma_capability_t *capa);

/**
 * Initialize DMA session parameters
 *
 * Initialize an odp_dma_param_t to its default values.
 *
 * @param[out] param    Parameter structure to be initialized
 */
void odp_dma_param_init(odp_dma_param_t *param);

/**
 * Create DMA session
 *
 * @param name		DMA session name or NULL. Maximum string length is ODP_DMA_NAME_LEN.
 * @param param		DMA session parameters
 *
 * @return DMA session handle on success
 * @retval ODP_DMA_INVALID on failure
 */
odp_dma_t odp_dma_create(const char *name, const odp_dma_param_t *param);

/**
 * Destroy DMA session
 *
 * A DMA session may be destroyed only when there are no active transfers in the session (all
 * previously started transfers have completed).
 *
 * @param dma		DMA session to be destroyed
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_dma_destroy(odp_dma_t dma);

/**
 * Find DMA session by name
 *
 * @param name          DMA session name
 *
 * @return Handle of the first matching DMA session
 * @retval ODP_DMA_INVALID  DMA session could not be found
 */
odp_dma_t odp_dma_lookup(const char *name);

/**
 * Initialize DMA transfer parameters
 *
 * Initialize an odp_dma_transfer_param_t to its default values.
 *
 * @param[out] trs_param     Parameter structure to be initialized
 */
void odp_dma_transfer_param_init(odp_dma_transfer_param_t *trs_param);

/**
 * Initialize DMA transfer completion parameters
 *
 * Initialize an odp_dma_compl_param_t to its default values.
 *
 * @param[out] compl_param   Parameter structure to be initialized
 */
void odp_dma_compl_param_init(odp_dma_compl_param_t *compl_param);

/**
 * Perform DMA transfer
 *
 * Performs DMA transfer according to the session and transfer parameters. Returns 1 when
 * the transfer was completed successfully. Returns 0 when the transfer was not performed
 * due to resources being temporarily busy. In this case, the same transfer is likely to succeed
 * after enough resources are available. Returns <0 on failure.
 *
 * The call outputs optionally transfer results on a non-zero return value. Use NULL as 'result'
 * pointer if results are not required.
 *
 * @param dma           DMA session
 * @param trs_param     Transfer parameters
 * @param[out] result   Pointer to transfer result structure for output, or NULL when not used
 *
 * @retval 1  when transfer completed successfully
 * @retval 0  when resources are busy and transfer was not performed
 * @retval <0 on failure
 */
int odp_dma_transfer(odp_dma_t dma, const odp_dma_transfer_param_t *trs_param,
		     odp_dma_result_t *result);

/**
 * Perform multiple DMA transfers
 *
 * Like odp_dma_transfer(), but performs 'num' transfers.
 *
 * @param dma           DMA session
 * @param trs_param     Array of transfer parameter pointers
 * @param[out] result   Array of transfer result pointers for output, or NULL when not used
 * @param num           Number of transfers to perform. Both arrays have this many elements.
 *
 * @return Number of transfers completed successfully (1 ... num)
 * @retval 0  when resources are busy and no transfers were performed
 * @retval <0 on failure
 */
int odp_dma_transfer_multi(odp_dma_t dma, const odp_dma_transfer_param_t *trs_param[],
			   odp_dma_result_t *result[], int num);

/**
 * Start DMA transfer
 *
 * Starts asynchronous DMA transfer according to the session and transfer parameters.
 * Completion parameters specify how transfer completion is reported. Returns 1 when the transfer
 * was started successfully. Returns 0 when the transfer was not started due to resources being
 * temporarily busy. In this case, the same transfer is likely to start successfully after enough
 * resources are available. Returns <0 on failure.
 *
 * @param dma           DMA session
 * @param trs_param     Transfer parameters
 * @param compl_param   Transfer completion parameters
 *
 * @retval 1  when transfer started successfully
 * @retval 0  when resources are busy and transfer was not started
 * @retval <0 on failure
 *
 * @see odp_dma_transfer_id_alloc(), odp_dma_transfer_done(), odp_dma_compl_result()
 */
int odp_dma_transfer_start(odp_dma_t dma, const odp_dma_transfer_param_t *trs_param,
			   const odp_dma_compl_param_t *compl_param);

/**
 * Start multiple DMA transfers
 *
 * Like odp_dma_transfer_start(), but starts 'num' transfers.
 *
 * @param dma           DMA session
 * @param trs_param     Array of transfer parameter pointers
 * @param compl_param   Array of transfer completion parameter pointers
 * @param num           Number of transfers to start. Both parameter arrays have this many elements.
 *
 * @return Number of transfers started successfully (1 ... num)
 * @retval 0  when resources are busy and no transfers were started
 * @retval <0 on failure
 */
int odp_dma_transfer_start_multi(odp_dma_t dma, const odp_dma_transfer_param_t *trs_param[],
				 const odp_dma_compl_param_t *compl_param[], int num);

/**
 * Check if DMA transfer has completed
 *
 * Application must call this function for every transfer that was started in ODP_DMA_COMPL_POLL
 * mode until a non-zero value is returned. The transfer identifier from completion parameters of
 * the transfer start call is used. When a non-zero value is returned, the transfer is complete
 * and the identifier may be freed or reused for another transfer.
 *
 * The call outputs optionally transfer results on a non-zero return value. Use NULL as 'result'
 * pointer if results are not required.
 *
 * @param dma          DMA session
 * @param transfer_id  Transfer identifier
 * @param[out] result  Pointer to transfer result structure for output, or NULL when not used.
 *
 * @retval 0  transfer has not finished
 * @retval >0 transfer has finished successfully
 * @retval <0 on failure
 */
int odp_dma_transfer_done(odp_dma_t dma, odp_dma_transfer_id_t transfer_id,
			  odp_dma_result_t *result);

/**
 * Allocate DMA transfer identifier
 *
 * Transfer identifiers are used in #ODP_DMA_COMPL_POLL mode. It identifies a previously started
 * transfer for an odp_dma_transfer_done() call. The maximum number of transfer identifiers is
 * implementation specific, but there are at least odp_dma_capability_t::max_transfers identifiers
 * per session.
 *
 * @param dma          DMA session
 *
 * @return Transfer identifier
 * @retval ODP_DMA_TRANSFER_ID_INVALID  Transfer identifier could not be allocated
 */
odp_dma_transfer_id_t odp_dma_transfer_id_alloc(odp_dma_t dma);

/**
 * Free DMA transfer identifier
 *
 * @param dma          DMA session
 * @param transfer_id  DMA transfer identifier to be freed
 */
void odp_dma_transfer_id_free(odp_dma_t dma, odp_dma_transfer_id_t transfer_id);

/**
 * Get printable value for DMA session handle
 *
 * @param dma   Handle to be converted for debugging
 *
 * @return      uint64_t value that can be used to print/display this handle
 */
uint64_t odp_dma_to_u64(odp_dma_t dma);

/**
 * Print debug info about DMA session
 *
 * Print implementation defined information about DMA session to the ODP log.
 * The information is intended to be used for debugging.
 *
 * @param dma      DMA session handle
 */
void odp_dma_print(odp_dma_t dma);

/**
 * Check DMA completion event
 *
 * Reads DMA completion event (ODP_EVENT_DMA_COMPL), and returns if the transfer succeeded or
 * failed. The call outputs optionally transfer results. Use NULL as 'result' pointer if results
 * are not required.
 *
 * @param dma_compl    DMA completion event
 * @param[out] result  Pointer to transfer result structure for output, or NULL when not used.
 *
 * @retval 0  Transfer was successful
 * @retval <0 Transfer failed
 */
int odp_dma_compl_result(odp_dma_compl_t dma_compl, odp_dma_result_t *result);

/**
 * Convert event to DMA completion event
 *
 * Converts an ODP_EVENT_DMA_COMPL type event to a DMA completion event.
 *
 * @param ev           Event handle
 *
 * @return DMA completion event handle
 */
odp_dma_compl_t odp_dma_compl_from_event(odp_event_t ev);

/**
 * Convert DMA completion event to event
 *
 * @param dma_compl    DMA completion event handle
 *
 * @return Event handle
 */
odp_event_t odp_dma_compl_to_event(odp_dma_compl_t dma_compl);

/**
 * Get printable value for DMA completion event handle
 *
 * @param dma_compl    Handle to be converted for debugging
 *
 * @return	uint64_t value that can be used to print/display this handle
 */
uint64_t odp_dma_compl_to_u64(odp_dma_compl_t dma_compl);

/**
 * Allocate DMA completion event
 *
 * Allocates a DMA completion event from a pool. The pool must have been created with
 * odp_dma_pool_create() call. All completion event metadata are set to their default values.
 *
 * @param pool         Pool handle
 *
 * @return DMA completion event handle
 * @retval ODP_DMA_COMPL_INVALID  Completion event could not be allocated
 */
odp_dma_compl_t odp_dma_compl_alloc(odp_pool_t pool);

/**
 * Free DMA completion event
 *
 * Frees a DMA completion event into the pool it was allocated from.
 *
 * @param dma_compl    DMA completion event handle
 */
void odp_dma_compl_free(odp_dma_compl_t dma_compl);

/**
 * Print DMA completion event debug information
 *
 * Prints implementation specific debug information about
 * the completion event to the ODP log.
 *
 * @param dma_compl    DMA completion event handle
 */
void odp_dma_compl_print(odp_dma_compl_t dma_compl);

/**
 * Initialize DMA completion event pool parameters
 *
 * Initialize an odp_dma_pool_param_t to its default values.
 *
 * @param[out] pool_param     Parameter structure to be initialized
 */
void odp_dma_pool_param_init(odp_dma_pool_param_t *pool_param);

/**
 * Create DMA completion event pool
 *
 * Creates a pool of DMA completion events (ODP_EVENT_DMA_COMPL). Pool type is ODP_POOL_DMA_COMPL.
 * The use of pool name is optional. Unique names are not required. However, odp_pool_lookup()
 * returns only a single matching pool. Use odp_dma_pool_param_init() to initialize pool parameters
 * into their default values. Parameters values must not exceed pool capabilities
 * (odp_dma_pool_capability_t).
 *
 * @param name          Name of the pool or NULL. Maximum string length is ODP_POOL_NAME_LEN.
 * @param pool_param    Pool parameters
 *
 * @return Handle of the created pool
 * @retval ODP_POOL_INVALID  Pool could not be created
 */
odp_pool_t odp_dma_pool_create(const char *name, const odp_dma_pool_param_t *pool_param);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

