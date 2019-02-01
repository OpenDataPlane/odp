/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Compression
 */

#ifndef ODP_API_SPEC_COMP_H_
#define ODP_API_SPEC_COMP_H_

#include <odp/visibility_begin.h>
#include <odp/api/support.h>
#include <odp/api/packet.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_compression ODP COMP
 *  Operations for Compression and Decompression API.
 *  Hash calculation may be combined with de-/compression operations
 *
 *  @{
 */

/**
 * @def ODP_COMP_SESSION_INVALID
 * Invalid session handle
 */

/**
 * @typedef odp_comp_session_t
 * Compression/Decompression session handle
 */

/**
 * Compression operation mode
 */
typedef enum {
	/** Synchronous Compression operation
	 *
	 * Application uses synchronous operation,
	 * which outputs all results on function return.
	 * */
	ODP_COMP_OP_MODE_SYNC,

	/** Asynchronous Compression operation
	 *
	 * Application uses asynchronous operation,
	 * which return results via events.
	 * */
	ODP_COMP_OP_MODE_ASYNC
} odp_comp_op_mode_t;

/**
 * Compression operation type.
 */
typedef enum {
	/** Operation type - Compress */
	ODP_COMP_OP_COMPRESS,

	/** Operation type - Decompress */
	ODP_COMP_OP_DECOMPRESS
} odp_comp_op_t;

/**
 * Compression hash algorithms
 */
typedef enum {
	/** No hash algorithm selected. */
	ODP_COMP_HASH_ALG_NONE,

	/** SHA-1 hash algorithm. */
	ODP_COMP_HASH_ALG_SHA1,

	/** SHA-2 hash algorithm 256-bit digest length. */
	ODP_COMP_HASH_ALG_SHA256
} odp_comp_hash_alg_t;

/**
 * Compression algorithms
 *
 */
typedef enum {
	/** No algorithm specified. Added for testing purpose. */
	ODP_COMP_ALG_NULL,

	/** DEFLATE - RFC1951 */
	ODP_COMP_ALG_DEFLATE,

	/** ZLIB - RFC1950 */
	ODP_COMP_ALG_ZLIB,

	/** LZS */
	ODP_COMP_ALG_LZS
} odp_comp_alg_t;

/**
 * Compression operation status codes
 */
typedef enum {
	/** Operation completed successfully*/
	ODP_COMP_STATUS_SUCCESS,

	/** Operation terminated due to insufficient output buffer */
	ODP_COMP_STATUS_OUT_OF_SPACE_TERM,

	/** Operation failure */
	ODP_COMP_STATUS_FAILURE,
} odp_comp_status_t;

/**
 * Hash algorithms in a bit field structure
 */
typedef union odp_comp_hash_algos_t {
	/** hash algorithms */
	struct {
		/** ODP_COMP_HASH_ALG_NONE */
		uint32_t none	: 1;

		/** ODP_COMP_HASH_ALG_SHA1 */
		uint32_t sha1	: 1;

		/** ODP_COMP_HASH_ALG_SHA256 */
		uint32_t sha256	: 1;

	} bit;

	/** All bits of the bit field structure
	 *
	 * This field can be used to set/clear all flags, or bitwise
	 * operations over the entire structure.
	 */
	uint32_t all_bits;
} odp_comp_hash_algos_t;

/**
 * Compression algorithms in a bit field structure
 */
typedef union odp_comp_algos_t {
	/** Compression algorithms */
	struct {
		/** ODP_COMP_ALG_NULL */
		uint32_t null       : 1;

		/** ODP_COMP_ALG_DEFLATE */
		uint32_t deflate    : 1;

		/** ODP_COMP_ALG_ZLIB */
		uint32_t zlib       : 1;

		/** ODP_COMP_ALG_LZS */
		uint32_t lzs        : 1;
	} bit;

	/** All bits of the bit field structure
	 * This field can be used to set/clear all flags, or bitwise
	 * operations over the entire structure.
	 */
	uint32_t all_bits;
} odp_comp_algos_t;

/**
 * Compression Interface Capabilities
 */
typedef struct odp_comp_capability_t {
	/** Maximum number of  sessions */
	uint32_t max_sessions;

	/** Supported compression algorithms */
	odp_comp_algos_t comp_algos;

	/** Supported hash algorithms */
	odp_comp_hash_algos_t hash_algos;

	/** Synchronous compression mode support (ODP_COMP_OP_MODE_SYNC) */
	odp_support_t sync;

	/** Aynchronous compression mode support (ODP_COMP_OP_MODE_ASYNC) */
	odp_support_t async;
} odp_comp_capability_t;

/**
 * Hash algorithm capabilities
 */
typedef struct odp_comp_hash_alg_capability_t {
	/** Digest length in bytes */
	uint32_t digest_len;
} odp_comp_hash_alg_capability_t;

/**
 * Compression algorithm capabilities
 */
typedef struct odp_comp_alg_capability_t {
	/** Maximum compression level supported by implementation of this
	 * algorithm. Indicates number of compression levels supported by
	 * implementation. Valid range from (1 ... max_level)
	 */
	uint32_t max_level;

	/** Supported hash algorithms */
	odp_comp_hash_algos_t hash_algo;

	/** Compression ratio
	 * Optimal compression operation ratio for this algorithm.
	 * This is an estimate of maximum compression operation output for this
	 * algorithm. It is expressed as a percentage of maximum expected
	 * output data size with respect to input data size.
	 * i.e a value of 200% denotes the output data is 2x times the input
	 * data size. This is an optimal/most case estimate and it is possible
	 * that the percentage of output data produced might be greater
	 * than this value.
	 *
	 * @see odp__percent_t
	 */
	odp_percent_t compression_ratio;
} odp_comp_alg_capability_t;

/**
 * Compression Huffman type. Used by DEFLATE algorithm
 */
typedef enum odp_comp_huffman_code {
	/** Fixed Huffman code */
	ODP_COMP_HUFFMAN_FIXED,

	/** Dynamic Huffman code */
	ODP_COMP_HUFFMAN_DYNAMIC,

	/** Default huffman code selected by implementation */
	ODP_COMP_HUFFMAN_DEFAULT,
} odp_comp_huffman_code_t;

/**
 * Compression DEFLATEe algorithm parameters.
 * Also initialized by other deflate based algorithms , ex. ZLIB
 */
typedef struct odp_comp_deflate_param {
	/**
	 * Compression level
	 *
	 * Valid range is integer between (0 ... max_level)
	 * level supported by the implementation.
	 *
	 * where,
	 * 0 - implementation default
	 *
	 * 1 - fastest compression i.e. output produced at
	 * best possible speed at the expense of compression quality
	 *
	 * max_level - High quality compression
	 *
	 * @see 'max_level' in odp_comp_alg_capability_t
	 */
	uint32_t comp_level;

	/** huffman code to use */
	odp_comp_huffman_code_t huffman_code;
} odp_comp_deflate_param_t;

/**
 * Compression algorithm specific parameters
 */
typedef union odp_comp_alg_param_t {
	/** deflate parameter */
	odp_comp_deflate_param_t deflate;

	/** Struct for defining zlib algorithm parameters */
	struct {
		/** deflate algo params */
		odp_comp_deflate_param_t deflate;
	} zlib;
} odp_comp_alg_param_t;

 /**
 * Compression session creation parameters
 */
typedef struct odp_comp_session_param_t {
	/** Compression operation type Compress vs Decompress */
	odp_comp_op_t op;

	/** Compression operation mode
	 *
	 * Operation mode Synchronous vs Asynchronous
	 *
	 * @see odp_comp_op(), odp_comp_op_enq()
	 */
	odp_comp_op_mode_t mode;

	/** Compression algorithm
	 *
	 *  @see odp_comp_capability()
	 */
	odp_comp_alg_t comp_algo;

	/** Hash algorithm
	 *
	 *  @see odp_comp_alg_capability()
	 */
	odp_comp_hash_alg_t hash_algo;

	/** parameters specific to compression */
	odp_comp_alg_param_t alg_param;

	/** Session packet enqueue ordering
	 * Boolean to indicate if packet enqueue ordering is required per
	 * session. Valid only for Asynchronous operation mode
	 * (ODP_COMP_OP_MODE_ASYNC). Packet order is always maintained for
	 * synchronous operation mode (ODP_COMP_OP_MODE_SYNC)
	 *
	 * true: packet session enqueue order maintained
	 *
	 * false: packet session enqueue order is not maintained
	 *
	 * @note: By disabling packet order requirement, performance oriented
	 * application can leverage HW offered parallelism to increase operation
	 * performance.
	 */
	odp_bool_t packet_order;

	/** Destination queue for compression operations result.
	 * Results are enqueued as ODP_EVENT_PACKET with subtype
	 * ODP_EVENT_PACKET_COMP
	 */
	odp_queue_t compl_queue;
} odp_comp_session_param_t;

/**
 * Compression packet operation result
 */
typedef struct odp_comp_packet_result_t {
	/** Operation status code */
	odp_comp_status_t status;

	/** Input packet handle */
	odp_packet_t pkt_in;

	/** Output packet data range
	 * Specifies offset and length of data resulting from compression
	 * operation. When hashing is configured output_data_range.len equals
	 * length of output data + length of digest.
	 */
	odp_packet_data_range_t output_data_range;
} odp_comp_packet_result_t;

/**
 * Compression per packet operation parameters
 */
typedef struct odp_comp_packet_op_param_t {
	/** Session handle */
	odp_comp_session_t session;

	/** Input data range to process. where,
	 *
	 * offset - starting offset
	 * length - length of data for compression operation
	 * */
	odp_packet_data_range_t in_data_range;

	/** Output packet data range.
	 * Indicates where processed packet will be written. where,
	 *
	 * offset - starting offset
	 * length - length of buffer available for output
	 *
	 * Output packet data is not modified outside of this provided data
	 * range. If output data length is not sufficient for compression
	 * operation ODP_COMP_STATUS_OUT_OF_SPACE_TERM error will occur
	 */
	odp_packet_data_range_t out_data_range;
} odp_comp_packet_op_param_t;

/**
 * Query compression capabilities
 *
 * Output compression capabilities on success.
 *
 * @param[out] capa   Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_comp_capability(odp_comp_capability_t *capa);

/**
 * Query supported compression algorithm capabilities
 *
 * Output algorithm capabilities.
 *
 * @param	comp	Compression algorithm
 * @param[out]	capa	Compression algorithm capability
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_comp_alg_capability(odp_comp_alg_t comp,
			    odp_comp_alg_capability_t *capa);

/**
 * Query supported hash algorithm capabilities
 *
 * Outputs all supported configuration options for the algorithm.
 *
 * @param	hash     Hash algorithm
 * @param	capa     Hash algorithm capability
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_comp_hash_alg_capability(odp_comp_hash_alg_t hash,
				 odp_comp_hash_alg_capability_t *capa);

/**
 * Initialize compression session parameters
 *
 * Initialize an odp_comp_session_param_t to its default values for
 * all fields.
 *
 * @param param   Pointer to odp_comp_session_param_t to be initialized
 */
void odp_comp_session_param_init(odp_comp_session_param_t *param);

/**
 * Compression session creation
 *
 * Create a comp session according to the session parameters. Use
 * odp_comp_session_param_init() to initialize parameters into their
 * default values.
 *
 * @param	param	Session parameters
 *
 * @retval		Comp session handle
 * @retval		ODP_COMP_SESSION_INVALID on failure
 */
odp_comp_session_t
odp_comp_session_create(const odp_comp_session_param_t *param);

/**
 * Compression session destroy
 *
 * Destroy an unused session. Result is undefined if session is being used
 * (i.e. asynchronous operation is in progress).
 *
 * @param	session		Session handle
 *
 * @retval	0 on success
 * @retval	<0 on failure
 */
int odp_comp_session_destroy(odp_comp_session_t session);

/**
 * Synchronous packet compression operation
 *
 * This operation does packet compression in synchronous mode. A successful
 * operation returns the number of successfully processed input packets and
 * updates the results in the corresponding output packets. Outputted packets
 * contain compression results metadata (odp_comp_packet_result_t), which
 * should be checked for operation status. Length of outputted data can be got
 * from output_data_range.len.
 *
 * When hashing is configured along with compression operation the
 * result is appended at the end of the output data, output_data_range.len
 * equals length of output data + 'digest_len'. Processed data length
 * can be computed by subtracting 'digest_len' from output_data_range.len where
 * 'digest_len' can be queried from odp_comp_hash_alg_capability().
 * Hash is always performed on plain text. Hash validation in decompression is
 * performed by the application.
 * For every input packet entry in 'pkt_in' array, application should pass
 * corresponding valid output packet handle. If any error occurs during
 * processing of packets, the API returns with number of entries successfully
 * processed.
 * Output packet metadatas like length or data pointer will not be updated.
 *
 * @param          pkt_in	Packets to be processed
 * @param          pkt_out	Packet handle array for resulting packets
 * @param          num_pkt	Number of packets to be processed
 * @param          param	Operation parameters
 *
 * @return Number of input packets consumed (0 ... num_pkt)
 * @retval <0 on failure
 *
 * @note The 'pkt_in','pkt_out'and 'param' arrays should be of same length,
 * Results are undefined if otherwise.

 * @note Same packet handle cannot be used as input and output parameter.
 * In-place compression operation is not supported
 */
int odp_comp_op(const odp_packet_t pkt_in[], odp_packet_t pkt_out[],
		int num_pkt, const odp_comp_packet_op_param_t param[]);

/**
 * Asynchronous packet compression  operation
 *
 * This operation does packet compression in asynchronous mode. It processes
 * packets otherwise identical to odp_comp_op(), but the resulting packets are
 * enqueued to 'compl_queue' configured during session (odp_comp_session_t)
 * creation. For every input packet entry in in_pkt array, user should pass
 * corresponding valid output packet handle. On return, API returns with
 * number of entries successfully submitted for operation.
 *
 * When hashing is configured along with compression operation the
 * result is appended at the end of the output data, output_data_range.len
 * equals length of output data + 'digest_len'. Processed data length
 * can be computed by subtracting 'digest_len' from output_data_range.len where
 * 'digest_len' can be queried from odp_comp_hash_alg_capability().
 * Hash is always performed on plain text. Hash validation in decompression is
 * performed by the application.
 *
 * In case of partially accepted array i.e.
 * when number of packets returned < num_pkt, application may attempt to
 * resubmit subsequent entries via calling any of the operation API.
 *
 * All the packets successfully enqueued will be submitted to 'compl_queue'
 * after compression operation, Application should check 'status' of the
 * operation in odp_comp_packet_result_t.
 * Output packet metadatas like length or data pointer will not be updated.
 *
 * Please note it is always recommended that application using async mode,
 * provide sufficiently large buffer size to avoid
 * ODP_COMP_STATUS_OUT_OF_SPACE_TERM.
 *
 * @param	pkt_in		Packets to be processed
 * @param	pkt_out		Packet handle array for resulting packets
 * @param	num_pkt		Number of packets to be processed
 * @param	param		Operation parameters
 *
 * @return	Number of input packets enqueued (0 ... num_pkt)
 * @retval	<0 on failure
 *
 * @note The 'pkt_in','pkt_out'and 'param' arrays should be of same length,
 * Results are undefined if otherwise.

 * @note Same packet handle cannot be used as input and output parameter.
 * In-place compression operation is not supported

 * @see odp_comp_op(), odp_comp_packet_result()
 */
int odp_comp_op_enq(const odp_packet_t pkt_in[], odp_packet_t pkt_out[],
		    int num_pkt, const odp_comp_packet_op_param_t param[]);

/**
 * Get compression operation results from processed packet.
 *
 * Successful compression operations of all modes (ODP_COMP_OP_MODE_SYNC and
 * ODP_COMP_OP_MODE_ASYNC) produce packets which contain compression result
 * metadata. This function copies operation results from compression processed
 * packet. Event subtype of this packet is ODP_EVENT_PACKET_COMP. Results are
 * undefined if non-compression processed packet is passed as input.
 *
 * @param[out]    result  pointer to operation result for output
 * @param	  packet  compression processed packet (ODP_EVENT_PACKET_COMP)
 *
 * @retval  0     On success
 * @retval <0     On failure
 */
int odp_comp_result(odp_comp_packet_result_t *result, odp_packet_t packet);

 /**
  * Convert compression processed packet event to packet handle
  *
  * Get packet handle corresponding to processed packet event. Event subtype
  * must be ODP_EVENT_PACKET_COMP. Compression operation results can be
  * examined with odp_comp_result().
  *
  * @param	event	Event handle
  *
  * @return	Valid Packet handle on success,
  * @retval	ODP_PACKET_INVALID on failure
  *
  * @see odp_event_subtype(), odp_comp_result()
  *
  */
odp_packet_t odp_comp_packet_from_event(odp_event_t event);

 /**
  * Convert processed packet handle to event
  *
  * The packet handle must be an output of a compression operation
  *
  * @param	pkt	Packet handle from compression operation
  * @return Event handle
  */
odp_event_t odp_comp_packet_to_event(odp_packet_t pkt);

/**
 * Get printable value for an odp_comp_session_t
 *
 * @param hdl  odp_comp_session_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_comp_session_t handle.
 */
uint64_t odp_comp_session_to_u64(odp_comp_session_t hdl);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

