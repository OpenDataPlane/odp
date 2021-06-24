/* Copyright (c) 2021, Nokia
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

#include <odp/api/queue.h>
#include <odp/api/std_types.h>

/** @defgroup odp_dma ODP DMA
 *  Direct Memory Access operations.
 *  @{
 */

/**
 * @typedef odp_dma_t
 * DMA session
 */

/**
 * @def ODP_DMA_INVALID
 * Invalid DMA session
 */

/**
 * @typedef odp_dma_transfer_id_t
 * DMA transfer operation identifier
 */

/**
 * @def ODP_DMA_TRANSFER_ID_INVALID
 * Invalid DMA transfer operation identifier
 */

/**
 * @def ODP_DMA_NAME_LEN
 * Maximum DMA name length in chars including null char
 */

/**
 * DMA transfer direction
 *
 * Transfers within the main memory is the only API specification defined option. Some
 * implementations may extend this enumeration with implementation specific memory types.
 */
typedef enum odp_dma_direction_t {
	/** DMA transfer within the main memory (usually DRAM) */
	ODP_DMA_MAIN_TO_MAIN = 0

} odp_dma_direction_t;

/**
 * DMA transfer completion mode
 */
typedef enum odp_dma_compl_mode_t {
	/** No completion indication */
	ODP_DMA_COMPL_NONE = 0,

	/** Synchronous transfer
	 *
	 *  odp_dma_transfer_sync() call does the transfer operation and returns when it
	 *  has finished. */
	ODP_DMA_COMPL_SYNC,

	/** Asynchronous transfer with completion event
	 *
	 *  odp_dma_transfer_start() call starts a transfer operation and a completion event
	 *  indicates when the operation has finished. */
	ODP_DMA_COMPL_EVENT,

	/** Asynchronous transfer operation with completion polling
	 *
	 *  odp_dma_transfer_start() call starts a transfer operation and application uses
	 *  odp_dma_transfer_status() call to check if operation has finished. */
	ODP_DMA_COMPL_POLL,

	/** Both (event and poll) asynchronous transfer methods used
	 *
	 *  Application uses both asynchronous transfer methods (event and poll)
	 *  within a session. Transfer completion parameter odp_dma_compl_param_t::mode selects
	 *  which one is used on a transfer. */
	ODP_DMA_COMPL_EVENT_AND_POLL

} odp_dma_compl_mode_t;

/**
 * DMA transfer data format
 */
typedef enum odp_dma_data_format_t {
	/** Data format is raw memory address */
	ODP_DMA_FORMAT_ADDR = 0,

	/** Data format is odp_packet_t */
	ODP_DMA_FORMAT_PACKET,

	/** Data format is odp_buffer_t */
	ODP_DMA_FORMAT_BUFFER

} odp_dma_data_format_t;

/**
 * DMA transfer ordering
 */
typedef enum odp_dma_transfer_order_t {
	/** No specific ordering between transfers
	 *
	 *  This may result the best performance (maximum implementation parallelism) as
	 *  transfers may start and complete in any order. */
	ODP_DMA_NO_ORDER = 0,

	/** Maintain transfer operation order
	 *
	 *  Perform transfers and report completions in the same order they were started
	 *  within a session. */
	ODP_DMA_ORDER_TRANSFER,

	/** Maintain transfer completion order
	 *
	 *  Data transfers may be performed in any order, but transfer completions must be reported
	 *  in the same order they were started within a session. This allows application to
	 *  start multiple transfers and wait only completion of the last one. */
	ODP_DMA_ORDER_TRANSFER_COMPL

} odp_dma_transfer_order_t;

/**
 * DMA transfer operation mode
 */
typedef enum odp_dma_op_mode_t {
	/** Multi-thread safe operation
	 *
	 *  Multiple threads may perform DMA transfers concurrently on the same DMA session.
	 */
	ODP_DMA_OP_MT = 0,

	/** Single thread operation
	 *
	 *  Multiple threads may perform DMA transfers on the same DMA session, but application
	 *  ensures that transfer operations (start and status calls) are not performed
	 *  concurrently from multiple threads.
	 */
	ODP_DMA_OP_ST

} odp_dma_op_mode_t;

/**
 * DMA capabilities
 */
typedef struct odp_dma_capability {
	/** Maximum number of DMA sessions */
	uint32_t max_sessions;

	/** Maximum number of source segments in a single transfer */
	uint32_t max_src_segs;

	/** Maximum number of destination segments in a single transfer */
	uint32_t max_dst_segs;

	/** Maximum number of destination and source segments combined in a single transfer */
	uint32_t max_segs;

	/** Maximum segment length in bytes
	 *
	 *  This is the maximum length of any source or destination segment. */
	uint32_t max_seg_len;

	/* TODO:
	 * - formats: addr, buffer, packet, src/dst mixes?
	 * - compl modes
	 * - ordering
	 * - completion queue type: plain vs sched
	 * - free source event
	 */

} odp_dma_capability_t;

/**
 * DMA session parameters
 */
typedef struct odp_dma_param_t {
	/** Transfer direction
	 *
	 *  The default value is ODP_DMA_MAIN_TO_MAIN.
	 */
	odp_dma_direction_t direction;

	/** Transfer completion mode
	 *
	 *  The default value is ODP_DMA_COMPL_SYNC.
	 */
	odp_dma_compl_mode_t compl_mode;

	/** Transfer operation multi-thread safety
	 *
	 *  The default value is ODP_DMA_OP_MT.
	 */
	odp_dma_op_mode_t op_mode;

	/** Source data format
	 *
	 *  The default value is ODP_DMA_FORMAT_ADDR.
	 */
	odp_dma_data_format_t src_format;

	/** Destination data format
	 *
	 *  The default value is ODP_DMA_FORMAT_ADDR.
	 */
	odp_dma_data_format_t dst_format;

	/** Data transfer ordering
	 *
	 *  The default value is ODP_DMA_NO_ORDER.
	 */
	odp_dma_transfer_order_t order;

} odp_dma_param_t;

/**
 * DMA segment
 */
typedef struct odp_dma_seg_t {
	/** Segment start address or offset */
	union {
		/** Segment start address in memory when format is ODP_DMA_FORMAT_ADDR */
		void *addr;

		/** Segment start as an offset into packet or buffer */
		struct {
			/** Union of handles */
			union {
				/** Packet handle when format is ODP_DMA_FORMAT_PACKET */
				odp_packet_t packet;

				/** Buffer handle when format is ODP_DMA_FORMAT_BUFFER */
				odp_buffer_t buffer;
			};

			/** Segment start offset into the packet or buffer */
			uint32_t offset;
		};
	};

	/** Segment length in bytes
	 *
	 *  Maximum value is defined by max_seg_len capability. */
	uint32_t len;

	/* TODO: allow under and overflow of writes: dst ptr +- a cache line ? */

} odp_dma_seg_t;

/**
 * DMA transfer parameters
 *
 * These parameters define data sources and destinations for a DMA transfer. Capabilities specify
 * the maximum number of segments and the maximum segment length that are supported. Total length
 * of source and destination segments must be equal. Segment memory areas must not overlap.
 * Data transfer from source to destination segment(s) may happen in any (segment and byte) order.
 *
 * Two transfers may read/write overlapping memory areas, but an appropriate transfer ordering
 * option (e.g. ODP_DMA_ORDER_TRANSFER) needs to be used for correct operation. All data writes of
 * a transfer are visible to all memory observers (threads and HW accelerators) before the transfer
 * is reported as complete.
 *
 * The selected data format specifies how segment structure fields are used. For each segment:
 *
 * ODP_DMA_FORMAT_ADDR:
 *     Set segment start address (odp_dma_seg_t::addr) and length.
 * ODP_DMA_FORMAT_BUFFER:
 *     Set buffer handle (odp_dma_seg_t::buffer), segment start offset (odp_dma_seg_t::offset)
 *     and length. Offsets are calculated from odp_buffer_addr().
 * ODP_DMA_FORMAT_PACKET:
 *     Set packet handle (odp_dma_seg_t::packet), segment start offset (odp_dma_seg_t::offset)
 *     and length. Offsets are calculated from odp_packet_data(). If a DMA segment spans over
 *     multiple (e.g. two) packet segments, it is consired as equally many (e.g. two) DMA segments.
 *     So, take packet segmentation into account when making sure that maximum number of
 *     DMA segment capabilities are not exceeded.
 */
typedef struct odp_dma_transfer_param_t {
	/** Number of source segments */
	uint32_t num_src;

	/** Number of destination segments */
	uint32_t num_dst;

	/** Pointer to source segment table. The table has 'num_src' entries. */
	odp_dma_seg_t *src_seg;

	/** Pointer to destination segment table. The table has 'num_dst' entries. */
	odp_dma_seg_t *dst_seg;

	/** Free source packets or buffers
	 *
	 *  When set, free the source packets/buffers back into their originating pool after
	 *  a successful operation.
	 *
	 *  The default value is false.
	 *
	 *  TODO: free source per segment, or per transfer
	 */
	odp_bool_t free_src;

} odp_dma_transfer_param_t;

/**
 * DMA transfer completion parameters
 */
typedef struct odp_dma_compl_param_t {
	/** Completion mode
	 *
	 *  Select a completion mode: ODP_DMA_COMPL_EVENT, ODP_DMA_COMPL_POLL or ODP_DMA_COMPL_NONE.
	 *  The mode must match session parameter odp_dma_param_t::compl_mode value. If session
	 *  was created with ODP_DMA_COMPL_EVENT_AND_POLL, this selects between ODP_DMA_COMPL_EVENT
	 *  and ODP_DMA_COMPL_POLL.
	 *
	 *  ODP_DMA_COMPL_NONE can be used to specify that completion indication is not requested.
	 *  Application may e.g. start a series of transfers and request completion indication
	 *  only on the last one.
	 *
	 *  The default value is ODP_DMA_COMPL_NONE.
	 */
	odp_dma_compl_mode_t mode;

	/** Completion event
	 *
	 *  This event is sent to the completion queue when the transfer is complete. Event type
	 *  must be either ODP_EVENT_BUFFER or ODP_EVENT_PACKET. The same event may be used also
	 *  as a transfer destination or source.
	 */
	odp_event_t event;

	/** Completion queue */
	odp_queue_t queue;

	/** Transfer identifier for polling
	 *
	 *  odp_dma_transfer_start() sets this in ODP_DMA_COMPL_POLL mode. Application
	 *  passes it to odp_dma_transfer_status() call to check if the transfer has completed.
	 */
	odp_dma_transfer_id_t transfer_id;

} odp_dma_compl_param_t;

/**
 * Query DMA capabilities
 *
 * Outputs DMA capabilities on success.
 *
 * @param[out] capa  Pointer to a capability structure for output
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
 * @param param         Parameter structure to be initialized
 */
void odp_dma_param_init(odp_dma_param_t *param);

/**
 * Create a DMA session
 *
 * @param name		DMA session name or NULL. Maximum string length is ODP_DMA_NAME_LEN.
 * @param param		DMA session parameters
 *
 * @retval DMA session handle on success
 * @retval ODP_DMA_INVALID on failure
 */
odp_dma_t odp_dma_create(const char *name, const odp_dma_param_t *param);

/**
 * Destroy DMA session
 *
 * @param dma		DMA session to be destroyed
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_dma_destroy(odp_dma_t dma);

/**
 * Find a DMA session by name
 *
 * @param name          DMA session name
 *
 * @retval Handle of the first matching DMA session
 * @retval ODP_DMA_INVALID  DMA session could not be found
 */
odp_dma_t odp_dma_lookup(const char *name);

/**
 * Initialize DMA transfer parameters
 *
 * Initialize an odp_dma_transfer_param_t to its default values.
 *
 * @param param         Parameter structure to be initialized
 */
void odp_dma_transfer_param_init(odp_dma_transfer_param_t *param);

/**
 * Initialize DMA transfer completion parameters
 *
 * Initialize an odp_dma_compl_param_t to its default values.
 *
 * @param param         Parameter structure to be initialized
 */
void odp_dma_compl_param_init(odp_dma_compl_param_t *param);

/**
 * Synchronous DMA transfer operation
 *
 * Transfers data according to the parameters and returns when the transfer is complete.
 *
 * @param dma           DMA session
 * @param transfer      Transfer parameters
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_dma_transfer_sync(odp_dma_t dma, const odp_dma_transfer_param_t *transfer);

/**
 * Start DMA transfer
 *
 * Start asynchronous DMA transfer operation. Transfer parameters specify data to be transferred.
 * Completion parameters specify how transfer completion is reported.
 *
 * @param         dma           DMA session
 * @param         transfer      Transfer parameters
 * @param[in,out] completion    Transfer completion parameters
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_dma_transfer_start(odp_dma_t dma, const odp_dma_transfer_param_t *transfer,
			   odp_dma_compl_param_t *completion);

/**
 * Start multiple DMA transfers
 *
 * Like odp_dma_transfer_start(), but starts 'num' transfers.
 *
 * @param         dma           DMA session
 * @param         transfer      Array of transfer parameters
 * @param[in,out] completion    Array of transfer completion parameters
 * @param         num           Number of transfers to start. Both parameter arrays have this
 *                              many elements.
 *
 * @retval Number of transfers started successfully (0 ... num)
 * @retval <0 on failure
 */
int odp_dma_transfer_start_multi(odp_dma_t dma, const odp_dma_transfer_param_t *transfer[],
				 odp_dma_compl_param_t *completion[], int num);

/**
 * Check if a DMA transfer has completed
 *
 * Application must call this function for every transfer that was started in poll mode until
 * a non-zero value is returned. Transfer identifier from a previous transfer start call is used.
 * The identifier is used as long as zero is returned. When a non-zero value is returned,
 * the transfer has completed (either successfully or into a failure) and the identifier must not
 * be used anymore.
 *
 * @param dma          DMA session
 * @param transfer_id  Transfer identifier
 *
 * @retval 0  transfer has not finished
 * @retval >0 transfer has finished successfully
 * @retval <0 on failure
 */
int odp_dma_transfer_status(odp_dma_t dma, odp_dma_transfer_id_t transfer_id);

/**
 * Get printable value for a DMA session handle
 *
 * @param dma	Handle to be converted for debugging
 *
 * @return	uint64_t value that can be used to print/display this handle
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
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

