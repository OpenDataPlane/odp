/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Nokia
 */

/**
 * @file
 *
 * ODP DMA
 */

#ifndef ODP_API_SPEC_DMA_TYPES_H_
#define ODP_API_SPEC_DMA_TYPES_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/event_types.h>
#include <odp/api/packet_types.h>
#include <odp/api/queue_types.h>
#include <odp/api/std_types.h>

/** @defgroup odp_dma ODP DMA
 *  DMA offload
 *  @{
 */

/**
 * @typedef odp_dma_t
 * DMA session
 */

/**
 * @typedef odp_dma_transfer_id_t
 * DMA transfer identifier
 */

/**
 * @typedef odp_dma_compl_t
 * DMA completion event
 */

/**
 * @def ODP_DMA_INVALID
 * Invalid DMA session
 */

/**
 * @def ODP_DMA_TRANSFER_ID_INVALID
 * Invalid DMA transfer identifier
 */

/**
 * @def ODP_DMA_COMPL_INVALID
 * Invalid DMA completion event
 */

/**
 * @def ODP_DMA_NAME_LEN
 * Maximum DMA name length, including the null character
 */

/**
 * DMA completion event pool capabilities
 *
 * Pool statistics are not supported with DMA completion event pools.
 */
typedef struct odp_dma_pool_capability_t {
	/** Maximum number of DMA completion event pools
	 *
	 *  See odp_pool_capability_t::max_pools for total capability. */
	uint32_t max_pools;

	/** Maximum number of DMA completion events in a pool */
	uint32_t max_num;

	/** Maximum user area size in bytes */
	uint32_t max_uarea_size;

	/** Pool user area persistence
	 *
	 *  See buf.uarea_persistence of odp_pool_capability_t for details
	 *  (odp_pool_capability_t::uarea_persistence). */
	odp_bool_t uarea_persistence;

	/** Minimum size of thread local cache */
	uint32_t min_cache_size;

	/** Maximum size of thread local cache */
	uint32_t max_cache_size;

} odp_dma_pool_capability_t;

/**
 * DMA completion event pool parameters
 */
typedef struct odp_dma_pool_param_t {
	/** Number of DMA completion events in the pool
	 *
	 *  Maximum value is defined by 'max_num' pool capability */
	uint32_t num;

	/** User area size in bytes
	 *
	 *  Maximum value is defined by 'max_uarea_size' pool capability. Specify as 0 if no user
	 *  area is needed. The default value is 0.
	 */
	uint32_t uarea_size;

	/** Parameters for user area initialization */
	struct {
		/** See uarea_init.init_fn of odp_pool_param_t for details
		 *  (odp_pool_param_t::init_fn). Function is called during
		 *  odp_dma_pool_create(). */
		void (*init_fn)(void *uarea, uint32_t size, void *args, uint32_t index);

		/** See uarea_init.args of odp_pool_param_t for details
		 *  (odp_pool_param_t::args). */
		void *args;

	} uarea_init;

	/** Maximum number of events cached locally per thread
	 *
	 *  See odp_pool_param_t::cache_size documentation for details. Valid values range from
	 *  'min_cache_size' to 'max_cache_size' capability. The default value is implementation
	 *  specific and set by odp_dma_pool_param_init().
	 */
	uint32_t cache_size;

} odp_dma_pool_param_t;

/* Includes pool_types.h, which depends on odp_dma_pool_param_t. */
#include <odp/api/queue_types.h>

/**
 * DMA transfer direction
 *
 * Transfer direction defines source and destination memory type of DMA transfers. API specification
 * defines only one option (#ODP_DMA_MAIN_TO_MAIN) for the transfer direction. It is used for
 * transfers within the main memory. Some implementations may extend this enumeration with
 * implementation specific directions and memory types (e.g. from main memory to a device, etc.).
 */
typedef uint32_t odp_dma_direction_t;

/** DMA transfer within the main memory */
#define ODP_DMA_MAIN_TO_MAIN 0x1u

/**
 * DMA transfer type
 *
 * Transfer type defines how DMA transfers operate data. Currently, only one transfer type is
 * defined (#ODP_DMA_TYPE_COPY).
 *
 */
typedef uint32_t odp_dma_transfer_type_t;

/** Copy data
 *
 *  Copy all data from source segment(s) to destination segment(s). There may be different
 *  number of source and destination segments in a transfer, but total length of all source
 *  segments must be equal to total length of all destination segments. Segments must not
 *  point to overlapping memory addresses. There are no alignment requirements for
 *  segment addresses or lengths. Data transfer from source to destination may happen
 *  in any segment and byte order.
 */
#define ODP_DMA_TYPE_COPY 0x1u

/**
 * DMA transfer completion mode
 *
 * Transfer completion mode defines how transfer completion is reported to the application.
 * Completion modes are: #ODP_DMA_COMPL_NONE, #ODP_DMA_COMPL_SYNC, #ODP_DMA_COMPL_EVENT, and
 * #ODP_DMA_COMPL_POLL
 *
 * If not otherwise specified, a DMA transfer is complete when memory reads and writes are complete
 * for all its segments, and writes are visible to all memory observers (threads and
 * HW accelerators).
 */
typedef uint32_t odp_dma_compl_mode_t;

/** No completion indication
 *
 *  Application uses odp_dma_transfer_start() call to start a DMA transfer, but does
 *  not request a completion notification for it. This can be useful for example when application
 *  starts a burst of transfers, but requests a completion event only on the last one
 *  (none on others).
 */
#define ODP_DMA_COMPL_NONE  0x1u

/** Synchronous transfer
 *
 *  Application uses odp_dma_transfer() call for DMA transfers. Each call performs
 *  the requested transfer and returns when the transfer is complete.
 */
#define ODP_DMA_COMPL_SYNC  0x2u

/** Asynchronous transfer with completion event
 *
 *  Application uses odp_dma_transfer_start() call to start a DMA transfer. The
 *  transfer is complete when application receives the completion event.
 */
#define ODP_DMA_COMPL_EVENT 0x4u

/** Asynchronous transfer with completion polling
 *
 *  Application uses odp_dma_transfer_start() call to start a DMA transfer and uses
 *  odp_dma_transfer_done() call to check if the transfer has completed.
 */
#define ODP_DMA_COMPL_POLL  0x8u

/**
 * DMA transfer data format
 */
typedef enum {
	/** Data format is raw memory address */
	ODP_DMA_FORMAT_ADDR = 0,

	/** Data format is odp_packet_t */
	ODP_DMA_FORMAT_PACKET

} odp_dma_data_format_t;

/**
 * DMA transfer ordering
 *
 * These options specify ordering of consecutive DMA transfers within a session. Transfer order
 * is defined by the order of consecutive transfer (start) calls and the order of transfers
 * within each multi-transfer call. Note that ordering option matters also when using
 * odp_dma_transfer_multi() call, as ODP_DMA_ORDER_NONE allows implementation to perform transfers
 * in parallel.
 *
 * These options do not apply to data (segment or byte) processing order within a transfer.
 * If two transfers read/write overlapping memory areas, an appropriate transfer ordering option
 * (e.g. ODP_DMA_ORDER_ALL) needs to be used for correct operation.
 */
typedef enum {
	/** No specific ordering between transfers
	 *
	 *  This may result the best performance (maximum implementation parallelism) as
	 *  transfers may start and complete in any order. */
	ODP_DMA_ORDER_NONE = 0,

	/** Report transfer completions in order
	 *
	 *  Transfers may be performed in any order, but transfer completions must be reported
	 *  in the same order they were started within a session. This allows application to
	 *  start multiple transfers and wait only completion of the last one. */
	ODP_DMA_ORDER_COMPL,

	/** Perform all transfers in order
	 *
	 *  Perform transfers and report their completions in the same order they were started
	 *  within a session. This enables for example a subsequent transfer to read data
	 *  written by a previous transfer. */
	ODP_DMA_ORDER_ALL

} odp_dma_transfer_order_t;

/**
 * DMA transfer multi-thread safeness
 */
typedef enum {
	/** Multi-thread safe operation
	 *
	 *  Multiple threads may perform DMA transfers concurrently on the same DMA session.
	 */
	ODP_DMA_MT_SAFE = 0,

	/** Application serializes operations
	 *
	 *  Multiple threads may perform DMA transfers on the same DMA session, but application
	 *  serializes all transfer related calls (odp_dma_transfer(), odp_dma_transfer_start(),
	 *  _start_multi(), _done() and _result()). Threads do not call any of these operations
	 *  concurrently.
	 */
	ODP_DMA_MT_SERIAL

} odp_dma_mt_mode_t;

/**
 * DMA capabilities
 */
typedef struct odp_dma_capability_t {
	/** Maximum number of DMA sessions
	 *
	 *  The value of zero means that DMA offload is not available.
	 */
	uint32_t max_sessions;

	/** Maximum number of transfers per DMA session
	 *
	 *  Maximum number of transfers that can be in-flight (started but not yet completed)
	 *  per session. When this limit is reached, new transfer requests may not be accepted
	 *  until some previously started transfers are complete. */
	uint32_t max_transfers;

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

	/** Supported completion modes
	 *
	 *  Each supported completion mode has a corresponding flag set in the mask.
	 *  Synchronous transfer (ODP_DMA_COMPL_SYNC) is always supported.
	 */
	odp_dma_compl_mode_t compl_mode_mask;

	/**
	 * Scheduled queue support
	 *
	 * 0: Scheduled queues are not supported as DMA completion queues
	 * 1: Scheduled queues are supported as DMA completion queues
	 */
	odp_bool_t queue_type_sched;

	/**
	 * Plain queue support
	 *
	 * 0: Plain queues are not supported as DMA completion queues
	 * 1: Plain queues are supported as DMA completion queues
	 */
	odp_bool_t queue_type_plain;

	/** DMA completion event pool capabilities */
	odp_dma_pool_capability_t pool;

	/** Source segment free support for data format type odp_packet_t
	 *
	 *  0: Source segment free feature is not supported
	 *  1: Source segment free feature is supported
	 */
	odp_bool_t src_seg_free;

	/** Destination segment allocation support for data format type odp_packet_t
	 *
	 *  0: Destination segment allocation feature is not supported
	 *  1: Destination segment allocation feature is supported
	 */
	odp_bool_t dst_seg_alloc;

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

	/** Transfer type
	 *
	 *  The default value is ODP_DMA_TYPE_COPY.
	 */
	odp_dma_transfer_type_t type;

	/** Transfer completion modes
	 *
	 *  Specify the completion modes application will use within the session.
	 *
	 *  Multiple modes may be selected, but it is implementation specific which combinations
	 *  are supported. If an unsupported combination is requested odp_dma_create() returns
	 *  a failure. See odp_dma_capability_t::compl_mode_mask for the supported modes.
	 */
	odp_dma_compl_mode_t compl_mode_mask;

	/** Transfer operation multi-thread safeness
	 *
	 *  The default value is ODP_DMA_MT_SAFE.
	 */
	odp_dma_mt_mode_t mt_mode;

	/** Transfer ordering
	 *
	 *  The default value is ODP_DMA_ORDER_NONE.
	 */
	odp_dma_transfer_order_t order;

} odp_dma_param_t;

/**
 * DMA segment
 */
typedef struct odp_dma_seg_t {
	/** Segment start address or packet handle */
	union {
		/** Segment start address in memory
		 *
		 *  Defines segment start when data format is #ODP_DMA_FORMAT_ADDR. Ignored with
		 *  other data formats.
		 */
		void *addr;

		/** Packet handle
		 *
		 *  Defines the packet when data format is #ODP_DMA_FORMAT_PACKET. Ignored
		 *  with other data formats. */
		odp_packet_t packet;

		/** Segment index
		 *
		 *  Defines a packet handle index with in the odp_dma_transfer_param_t::dst_seg
		 *  table to which this segment belongs to. When destination segment allocation
		 *  support is used, this index field can be used to merge multiple segments
		 *  into a single packet handle.
		 */
		uint16_t index;
	};

	/** Segment length in bytes
	 *
	 *  Defines segment length with all data formats. The maximum value is defined by
	 *  max_seg_len capability. When data format is #ODP_DMA_FORMAT_PACKET, the value must not
	 *  exceed odp_packet_len() - 'offset'.
	 */
	uint32_t len;

	/** Segment start offset into the packet
	 *
	 *  Defines segment start within the packet data. The offset is calculated from
	 *  odp_packet_data() position, and the value must not exceed odp_packet_len().
	 *  Ignored when data format is other than #ODP_DMA_FORMAT_PACKET.
	 */
	uint32_t offset;

	/** Segment hints
	 *
	 *  Depending on the implementation, setting these hints may improve performance.
	 *  Initialize all unused bits to zero.
	 */
	union {
		/** Segment hints bit field */
		struct {
			/** Allow full cache line access
			 *
			 *  When set to 1, data on the same cache line with the destination segment
			 *  is allowed to be overwritten. This hint is ignored on source segments.
			 */
			uint16_t full_lines : 1;
		};

		/** All bits of the bit field structure
		 *
		 *  This can be used to set/clear all bits, or to perform bitwise operations
		 *  on those.
		 */
		uint16_t all_hints;
	};

} odp_dma_seg_t;

/**
 * DMA transfer parameters
 *
 * These parameters define data sources and destinations for a DMA transfer. Capabilities specify
 * the maximum number of segments and the maximum segment length that are supported.
 *
 * The selected data format specifies how segment structure fields are used. When data format is
 * ODP_DMA_FORMAT_ADDR, set segment start address (odp_dma_seg_t::addr) and
 * length (odp_dma_seg_t::len). When data format is ODP_DMA_FORMAT_PACKET, set packet
 * handle (odp_dma_seg_t::packet), segment start offset (odp_dma_seg_t::offset) and length.
 * If a DMA segment spans over multiple packet segments, it is considered as equally many
 * DMA segments. So, take packet segmentation into account when making sure that the maximum
 * number of DMA segments capabilities are not exceeded.
 */
typedef struct odp_dma_transfer_param_t {
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

	/** Number of source segments
	 *
	 *  The default value is 1.
	 */
	uint32_t num_src;

	/** Number of destination segments
	 *
	 *  The default value is 1.
	 */
	uint32_t num_dst;

	/** Table of source segments
	 *
	 *  The table has 'num_src' entries. Data format is defined by 'src_format'.
	 */
	odp_dma_seg_t *src_seg;

	/** Table of destination segments
	 *
	 *  The table has 'num_dst' entries. Data format is defined by 'dst_format'.
	 */
	odp_dma_seg_t *dst_seg;

	/** Destination segment pool
	 *
	 *  If application chooses for destination segment allocation support, provide the pool
	 *  details from which the buffers need to be allocated.
	 */
	odp_pool_t dst_seg_pool;

	/** Transfer hints
	 *
	 *  Depending on the implementation, adjusting hints bit fields may improve performance.
	 *  Initialize all unused bits to zero.
	 */
	union {
		/** Hint bit fields */
		struct {
			/** Allow freeing all the source segments
			 *
			 *  When set to 1, all source segments with data format type odp_packet_t
			 *  are freed, packet free options (odp_packet_free_ctrl_t) does not affect
			 *  this bit.
			 */
			uint16_t seg_free : 1;

			/** Allow freeing all source segments to a single pool
			 *
			 *  When set to 1, all source segments with data format type odp_packet_t
			 *  are freed to a single pool.
			 */
			uint16_t single_pool : 1;

			/** Allow allocating all the destination segments
			 *
			 *  When set to 1, all the destination segments will be allocated from
			 *  dst_seg_pool.
			 */
			uint16_t seg_alloc : 1;
		};

		/** Entire bit field structure
		 *
		 *  This can be used to set or clear all bits, or to carry out bitwise operations
		 *  on those.
		 */
		uint16_t all;
	};

} odp_dma_transfer_param_t;

/**
 * DMA transfer completion parameters
 */
typedef struct odp_dma_compl_param_t {
	/** Completion mode
	 *
	 *  Select a completion mode: #ODP_DMA_COMPL_EVENT, #ODP_DMA_COMPL_POLL or
	 *  #ODP_DMA_COMPL_NONE. The mode must match one of the modes selected in session creation
	 *  parameters (odp_dma_param_t::compl_mode_mask).
	 *
	 *  ODP_DMA_COMPL_NONE can be used to specify that completion indication is not requested.
	 *  Application may for example start a series of transfers and request completion
	 *  indication only on the last one.
	 */
	odp_dma_compl_mode_t compl_mode;

	/** Transfer identifier
	 *
	 *  Transfer identifier is used in ODP_DMA_COMPL_POLL mode. Application passes the same
	 *  identifier here and to a later odp_dma_transfer_done() call to check transfer
	 *  completion status. Identifiers are allocated with odp_dma_transfer_id_alloc().
	 *  The identifier of a completed transfer may be reused for another transfer.
	 */
	odp_dma_transfer_id_t transfer_id;

	/** Completion event
	 *
	 *  When a transfer is started in ODP_DMA_COMPL_EVENT mode, this event is sent to
	 *  the completion queue when the transfer is complete. The event type must be
	 *  ODP_EVENT_DMA_COMPL. Use odp_dma_compl_result() to retrieve transfer results from
	 *  the event.
	 */
	odp_event_t event;

	/** Completion queue
	 *
	 *  The completion event is sent into this queue in ODP_DMA_COMPL_EVENT mode.
	 */
	odp_queue_t queue;

	/** User context pointer
	 *
	 *  User defined context pointer which is copied to transfer results (odp_dma_result_t). The
	 *  value does not need to represent a valid address (any intptr_t value is allowed).
	 *
	 *  The default value is NULL.
	 */
	void *user_ptr;

} odp_dma_compl_param_t;

/** DMA transfer results */
typedef struct odp_dma_result_t {
	/** DMA transfer success
	 *
	 *  true:  DMA transfer was successful
	 *  false: DMA transfer failed
	 */
	odp_bool_t success;

	/** User context pointer
	 *
	 *  User defined context pointer value from transfer completion parameters
	 *  (odp_dma_compl_param_t). The default value is NULL.
	 */
	void *user_ptr;

	/** Number of destination segments
	 *
	 * When destination buffer allocation feature is used, this value provides
	 * the number of segments in the destination segment table.
	 */
	uint32_t num_dst;

	/** Table of destination segments
	 *
	 * When destination buffer allocation feature is used, application provides the
	 * destination segment table of 'num_dst' size which gets filled with allocated
	 * destination segment details.
	 */
	odp_dma_seg_t *dst_seg;

} odp_dma_result_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

