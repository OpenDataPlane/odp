/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2021-2023 Nokia
 */

/**
 * @file
 *
 * ODP crypto
 */

#ifndef ODP_API_SPEC_CRYPTO_H_
#define ODP_API_SPEC_CRYPTO_H_
#include <odp/visibility_begin.h>

#include <odp/api/crypto_types.h>
#include <odp/api/deprecated.h>
#include <odp/api/packet_types.h>
#include <odp/api/std_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_crypto ODP CRYPTO
 *  Data ciphering and authentication.
 *  @{
 */

/**
 * Query crypto capabilities
 *
 * Outputs crypto capabilities on success.
 *
 * @param[out] capa   Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_crypto_capability(odp_crypto_capability_t *capa);

/**
 * Query supported cipher algorithm capabilities
 *
 * Outputs all supported configuration options for the algorithm. Output is
 * sorted (from the smallest to the largest) first by key length, then by IV
 * length.
 *
 * @param      cipher       Cipher algorithm
 * @param[out] capa         Array of capability structures for output
 * @param      num          Maximum number of capability structures to output
 *
 * @return Number of capability structures for the algorithm. If this is larger
 *         than 'num', only 'num' first structures were output and application
 *         may call the function again with a larger value of 'num'.
 * @retval <0 on failure
 */
int odp_crypto_cipher_capability(odp_cipher_alg_t cipher,
				 odp_crypto_cipher_capability_t capa[],
				 int num);

/**
 * Query supported authentication algorithm capabilities
 *
 * Outputs all supported configuration options for the algorithm. Output is
 * sorted (from the smallest to the largest) first by digest length, then by key
 * length.
 *
 * @param      auth         Authentication algorithm
 * @param[out] capa         Array of capability structures for output
 * @param      num          Maximum number of capability structures to output
 *
 * @return Number of capability structures for the algorithm. If this is larger
 *         than 'num', only 'num' first structures were output and application
 *         may call the function again with a larger value of 'num'.
 * @retval <0 on failure
 */
int odp_crypto_auth_capability(odp_auth_alg_t auth,
			       odp_crypto_auth_capability_t capa[], int num);

/**
 * Crypto session creation
 *
 * Create a crypto session according to the session parameters. Use
 * odp_crypto_session_param_init() to initialize parameters into their
 * default values. If call ends up with an error no new session will be
 * created.
 *
 * The parameter structure as well as the key and IV data pointed to by it
 * can be freed after the call.
 *
 * @param      param        Session parameters
 * @param[out] session      Created session else ODP_CRYPTO_SESSION_INVALID
 * @param[out] status       Failure code if unsuccessful
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_crypto_session_create(const odp_crypto_session_param_t *param,
			      odp_crypto_session_t *session,
			      odp_crypto_ses_create_err_t *status);

/**
 * Crypto session destroy
 *
 * Destroy an unused session. Result is undefined if session is being used
 * (i.e. asynchronous operation is in progress).
 *
 * @param session           Session handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_crypto_session_destroy(odp_crypto_session_t session);

/**
 * Get printable value for an odp_crypto_session_t
 *
 * @param hdl  odp_crypto_session_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_crypto_session_t handle.
 */
uint64_t odp_crypto_session_to_u64(odp_crypto_session_t hdl);

/**
 * Initialize crypto session parameters
 *
 * Initialize an odp_crypto_session_param_t to its default values for
 * all fields.
 *
 * @param param   Pointer to odp_crypto_session_param_t to be initialized
 */
void odp_crypto_session_param_init(odp_crypto_session_param_t *param);

/**
 * Return crypto processed packet that is associated with event
 *
 * Get packet handle to an crypto processed packet event. Event subtype must be
 * ODP_EVENT_PACKET_CRYPTO. Crypto operation results can be examined with
 * odp_crypto_result().
 *
 * Note: any invalid parameters will cause undefined behavior and may cause
 * the application to abort or crash.
 *
 * @param ev       Event handle
 *
 * @return Packet handle
 */
odp_packet_t odp_crypto_packet_from_event(odp_event_t ev);

/**
 * Convert crypto packet handle to event
 *
 * The packet handle must be an output of an crypto operation.
 *
 * @param pkt      Packet handle from crypto operation
 *
 * @return Event handle
 */
odp_event_t odp_crypto_packet_to_event(odp_packet_t pkt);

/**
 * Get crypto operation results from a crypto processed packet
 *
 * Crypto operations of all types (SYNC and ASYNC) produce packets which
 * contain crypto result metadata. This function returns success status
 * of the crypto operation that was applied to a packet and optionally
 * writes additional information in a result structure.
 *
 * If the crypto operation succeeded, zero is returned and the values
 * written in the cipher_status and auth_status fields of the result
 * structure have undefined values.
 *
 * If the crypto operation failed, -1 is returned and the cipher_status
 * and auth_status fields of the result structure indicate the reason for
 * the failure.
 *
 * The subtype of the passed packet must be ODP_EVENT_PACKET_CRYPTO,
 * otherwise the result of the call is undefined.
 *
 * @param         packet  A crypto processed packet (ODP_EVENT_PACKET_CRYPTO)
 * @param[out]    result  Pointer to operation result for output or NULL
 *
 * @retval   0    Crypto operation succeeded
 * @retval  -1    Crypto operation failed
 * @retval <-1    Failed to get crypto operation status of the packet
 */
int odp_crypto_result(odp_crypto_packet_result_t *result,
		      odp_packet_t packet);

/**
 * Crypto packet operation
 *
 * Performs the SYNC cryptographic operations specified during session creation
 * on the packets. All arrays should be of num_pkt size.
 *
 * Result of the crypto operation can be checked using odp_crypto_result().
 * Parse flags in packet metadata are not affected by the crypto operation.
 * In particular, odp_packet_has_error() can not be used for checking if the
 * crypto operation succeeded.
 *
 * Use of the pkt_out parameter depends on the configured crypto operation
 * type as described below.
 *
 * ODP_CRYPTO_OP_TYPE_LEGACY:
 *
 * Caller should initialize each element of pkt_out either with the desired
 * output packet handle or with ODP_PACKET_INVALID to make ODP allocate a new
 * packet from provided pool.
 *
 * All packet data and metadata are copied from the input packet to the output
 * packet before the requested crypto operation is performed to the output
 * packet. If an output packet is given to the operation, it must be at least
 * as long as the input packet and, in encode operations, long enough for the
 * hash result to be fully inside the packet data. Memory layout of the output
 * packet may change during the crypto operation. If the output packet is
 * longer than needed, it is not truncated and the extra data bytes retain
 * their content.
 *
 * It is ok to pass the same packet handle as both the input packet and the
 * output packet for the same crypto operation. In that case the input packet
 * is consumed but returned as the output packet (with possibly different
 * memory layout).
 *
 * ODP_CRYPTO_OP_TYPE_BASIC:
 *
 * ODP allocates the output packet from the pool from which the input
 * packet was allocated. The processed input packet is consumed. All
 * packet data and metadata are copied from the input packet to the output
 * packet before the requested crypto operation is applied to the output
 * packet. Memory layout (including packet data pointers, head and tail room,
 * segmentation) of the output packet may differ from that of the input
 * packet.
 *
 * The value of pktout[n] is ignored as pktout[n] is used purely as an
 * output parameter that returns the handle of the newly allocated packet.
 *
 * ODP_CRYPTO_OP_TYPE_OOP:
 *
 * Writes the output bytes of the crypto operation in a caller provided
 * output packet passed through pkt_out[n]. Input packets are not consumed
 * nor modified. Memory layout (including packet data pointers, head and
 * tail room, segmentation) of the output packet may change during the
 * operation.
 *
 * Crypto output is the processed crypto_range, auth_range and
 * MAC/digest (in encode sessions) of the input packet. The operation
 * behaves as if crypto range and auth range were first copied from the
 * input packet to the output packet and then the crypto operation
 * was applied to the output packet.
 *
 * Auth range of (AEAD) algorithms that ignore auth range is not copied.
 *
 * The offset of the crypto range and auth range in the output packet is
 * the same as in the input packet, adjusted by dst_offset_shift operation
 * parameter.
 *
 * pkt_out[n] must be a valid handle to a packet that is long enough to
 * contain the shifted crypto range, auth range and, in encode sessions,
 * the MAC/digest result. pkt_out[n] must not be the same as any input
 * packet or any other output packet.
 *
 * @param         pkt_in   Packets to be processed
 * @param[in,out] pkt_out  Packet handle array for resulting packets
 * @param         param    Operation parameters array
 * @param         num_pkt  Number of packets to be processed
 *
 * @return Number of input packets processed (0 ... num_pkt)
 * @retval <0 on failure
 */
int odp_crypto_op(const odp_packet_t pkt_in[],
		  odp_packet_t pkt_out[],
		  const odp_crypto_packet_op_param_t param[],
		  int num_pkt);

/**
 * Crypto packet operation
 *
 * Performs the ASYNC cryptographic operations specified during session
 * creation on the packets. Behaves otherwise like odp_crypto_op() but
 * returns output packets through events.
 *
 * With operation types other than ODP_CRYPTO_OP_TYPE_LEGACY, packet
 * data of processed packets may not be valid before odp_crypto_result()
 * has been called.
 *
 * With ODP_CRYPTO_OP_TYPE_OOP, an enqueued input packet is consumed but
 * returned back unmodified after the crypto operation is complete. The
 * caller may not access the input packet until getting the handle back
 * through odp_crypto_result().
 *
 * All arrays should be of num_pkt size, except that pkt_out parameter
 * is ignored when the crypto operation type is ODP_CRYPTO_OP_TYPE_BASIC.
 *
 * From packet ordering perspective this function behaves as if each input
 * packet was enqueued to a crypto session specific ODP queue in the order
 * the packets appear in the parameter array. The conceptual session input
 * queue has the same order type (ODP_QUEUE_ORDER_KEEP or
 * ODP_QUEUE_ORDER_IGNORE) as the completion queue of the session.
 * The order of output events of a crypto session in a completion queue is
 * the same as the order of the corresponding input packets in the conceptual
 * session input queue. The order of output events of different crypto
 * sessions is not defined even when they go through the same crypto
 * completion queue.
 *
 * @param pkt_in   Packets to be processed
 * @param pkt_out  Packet handle array for resulting packets
 * @param param    Operation parameters array
 * @param num_pkt  Number of packets to be processed
 *
 * @return Number of input packets consumed (0 ... num_pkt)
 * @retval <0 on failure
 */
int odp_crypto_op_enq(const odp_packet_t pkt_in[],
		      const odp_packet_t pkt_out[],
		      const odp_crypto_packet_op_param_t param[],
		      int num_pkt);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
