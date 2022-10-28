/* Copyright (c) 2016-2018, Linaro Limited
 * Copyright (c) 2021-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP IPsec API
 */

#ifndef ODP_API_SPEC_IPSEC_H_
#define ODP_API_SPEC_IPSEC_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/crypto_types.h>
#include <odp/api/event_types.h>
#include <odp/api/ipsec_types.h>
#include <odp/api/packet_types.h>
#include <odp/api/std_types.h>

/** @defgroup odp_ipsec ODP IPSEC
 *  IPSEC protocol offload.
 *  @{
 */

/**
 * Query IPSEC capabilities
 *
 * Outputs IPSEC capabilities on success.
 *
 * @param[out] capa   Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_ipsec_capability(odp_ipsec_capability_t *capa);

/**
 * Query supported IPSEC cipher algorithm capabilities
 *
 * Outputs all supported configuration options for the algorithm. Output is
 * sorted (from the smallest to the largest) first by key length, then by IV
 * length. Use this information to select key lengths, etc cipher algorithm
 * options for SA creation (odp_ipsec_crypto_param_t).
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
int odp_ipsec_cipher_capability(odp_cipher_alg_t cipher,
				odp_ipsec_cipher_capability_t capa[], int num);

/**
 * Query supported IPSEC authentication algorithm capabilities
 *
 * Outputs all supported configuration options for the algorithm. Output is
 * sorted (from the smallest to the largest) first by ICV length, then by key
 * length. Use this information to select key lengths, etc authentication
 * algorithm options for SA creation (odp_ipsec_crypto_param_t).
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
int odp_ipsec_auth_capability(odp_auth_alg_t auth,
			      odp_ipsec_auth_capability_t capa[], int num);

/**
 * Initialize IPSEC configuration options
 *
 * Initialize an odp_ipsec_config_t to its default values.
 *
 * @param[out] config  Pointer to IPSEC configuration structure
 */
void odp_ipsec_config_init(odp_ipsec_config_t *config);

/**
 * Global IPSEC configuration
 *
 * Initialize and configure IPSEC offload with global configuration options.
 * This must be called before any SAs are created. Use odp_ipsec_capability()
 * to examine which features and modes are supported. This function must be
 * called before creating the first SA with odp_ipsec_sa_create(). Calling this
 * function multiple times results in undefined behaviour.
 *
 * @param config   Pointer to IPSEC configuration structure
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_ipsec_capability(), odp_ipsec_config_init()
 */
int odp_ipsec_config(const odp_ipsec_config_t *config);

/**
 * Initialize IPSEC SA parameters
 *
 * Initialize an odp_ipsec_sa_param_t to its default values for all fields.
 *
 * @param param   Pointer to the parameter structure
 */
void odp_ipsec_sa_param_init(odp_ipsec_sa_param_t *param);

/**
 * Create IPSEC SA
 *
 * Create a new IPSEC SA according to the parameters.
 *
 * The parameter structure as well as all key, address and other memory
 * buffers pointed to by it can be freed after the call.
 *
 * @param param   IPSEC SA parameters
 *
 * @return IPSEC SA handle
 * @retval ODP_IPSEC_SA_INVALID on failure
 *
 * @see odp_ipsec_sa_param_init()
 */
odp_ipsec_sa_t odp_ipsec_sa_create(const odp_ipsec_sa_param_t *param);

/**
 * Disable IPSEC SA
 *
 * Application must use this call to disable a SA before destroying it. The call
 * marks the SA disabled, so that IPSEC implementation stops using it. For
 * example, inbound SPI lookups will not match any more. Application must
 * stop providing the SA as parameter to new IPSEC input/output operations
 * before calling disable. Packets in progress during the call may still match
 * the SA and be processed successfully.
 *
 * When in synchronous operation mode, the call will return when it's possible
 * to destroy the SA. In asynchronous mode, the same is indicated by an
 * ODP_EVENT_IPSEC_STATUS event sent to the queue specified for the SA. The
 * status event is guaranteed to be the last event for the SA, i.e. all
 * in-progress operations have completed and resulting events (including status
 * events) have been enqueued before it.
 *
 * @param sa      IPSEC SA to be disabled
 *
 * @retval 0      On success
 * @retval <0     On failure
 *
 * @see odp_ipsec_sa_destroy()
 */
int odp_ipsec_sa_disable(odp_ipsec_sa_t sa);

/**
 * Destroy IPSEC SA
 *
 * Destroy an unused IPSEC SA. Result is undefined if the SA is being used
 * (i.e. asynchronous operation is in progress).
 *
 * @param sa      IPSEC SA to be destroyed
 *
 * @retval 0      On success
 * @retval <0     On failure
 *
 * @see odp_ipsec_sa_create()
 */
int odp_ipsec_sa_destroy(odp_ipsec_sa_t sa);

/**
 * Printable format of odp_ipsec_sa_t
 *
 * @param sa      IPSEC SA handle
 *
 * @return uint64_t value that can be used to print/display this handle
 */
uint64_t odp_ipsec_sa_to_u64(odp_ipsec_sa_t sa);

/**
 * Inbound synchronous IPSEC operation
 *
 * This operation does inbound IPSEC processing in synchronous mode
 * (ODP_IPSEC_OP_MODE_SYNC). A successful operation returns the number of
 * packets consumed and outputs a new packet handle for each outputted packet.
 * Outputted packets contain IPSEC result metadata (odp_ipsec_packet_result_t),
 * which should be checked for transformation errors, etc. Outputted packets
 * with error status have undefined content, except that in case of sa_lookup
 * error the original input packet data is returned. The operation does not
 * modify packets that it does not consume. It cannot consume all input
 * packets if 'num_out' is smaller than 'num_in'.
 *
 * Packet context pointer and user area content are copied from input to output
 * packets. Output packets are allocated from the same pool(s) as input packets.
 *
 * When 'param.num_sa' is zero, this operation performs SA look up for each
 * packet. Otherwise, application must provide the SA(s) as part of operation
 * input parameters (odp_ipsec_in_param_t). The operation outputs used SA(s) as
 * part of per packet results (odp_ipsec_packet_result_t), or an error
 * status if a SA was not found.
 *
 * Each input packet must have a valid value for these metadata (other metadata
 * is ignored):
 * - L3 offset: Offset to the first byte of the (outmost) IP header
 * - L4 offset: When udp_encap is enabled, offset to the first byte of the
 *              encapsulating UDP header
 *
 * Additionally, implementation checks input IP packet length (odp_packet_len()
 * minus odp_packet_l3_offset()) against protocol headers and reports an error
 * (status.error.proto) if packet data length is less than protocol headers
 * indicate.
 *
 * Packets are processed in the input order. Packet order is maintained from
 * input 'pkt' array to output 'pkt' array. Packet order is not guaranteed
 * between calling threads.
 *
 * Input packets must not be IP fragments.
 *
 * The operation does packet transformation according to IPSEC standards (see
 * e.g. RFC 4302 and 4303). Resulting packets are well formed, reconstructed
 * original IP packets, with IPSEC headers removed and valid header field values
 * restored. The amount and content of packet data before the IP header is
 * undefined. Some amount of TFC padding may follow the IP packet payload,
 * in which case packet length is larger than protocol headers indicate.
 * TFC dummy packets have l3_type set to ODP_PROTO_L3_TYPE_NONE in tunnel mode
 * or l4_type set to ODP_PROTO_L4_TYPE_NO_NEXT in transport mode. Dummy
 * packets contain implementation specific amount of (dummy) data. Furthermore,
 * inline IPSEC processing may drop dummy packets.
 *
 * Each successfully transformed packet has a valid value for these metadata
 * regardless of the inner packet parse configuration
 * (odp_ipsec_inbound_config_t):
 * - l3_offset: Offset to the first byte of the original IP packet. The value
 *              is implementation specific for tunnel mode TFC dummy packets.
 * - l3_type:   Specifies if the original packet is IPv4 or IPv6. For tunnel
 *              mode TFC dummy packets set to ODP_PROTO_L3_TYPE_NONE.
 * - l4_type:   Always set to ODP_PROTO_L4_TYPE_NO_NEXT for transport mode dummy
 *              packets. Otherwise, depends on parse configuration. Default
 *              value is ODP_PROTO_L4_TYPE_NONE.
 * - pktio:     For inline IPSEC processed packets, original packet input
 *              interface
 *
 * Other metadata for parse results and error checks depend on configuration
 * (selected parse and error check levels).
 *
 * @param          pkt_in   Packets to be processed
 * @param          num_in   Number of packets to be processed
 * @param[out]     pkt_out  Packet handle array for resulting packets
 * @param[in, out] num_out  Number of resulting packets. Application sets this
 *                          to 'pkt_out' array size. A successful operation sets
 *                          this to the number of outputted packets
 *                          (1 ... num_out).
 * @param          param    Inbound operation parameters
 *
 * @return Number of input packets consumed (0 ... num_in)
 * @retval <0     On failure
 *
 * @see odp_packet_user_ptr(), odp_packet_user_area(), odp_packet_l3_offset(),
 * odp_packet_l4_offset()
 */
int odp_ipsec_in(const odp_packet_t pkt_in[], int num_in,
		 odp_packet_t pkt_out[], int *num_out,
		 const odp_ipsec_in_param_t *param);

/**
 * Outbound synchronous IPSEC operation
 *
 * This operation does outbound IPSEC processing in synchronous mode
 * (ODP_IPSEC_OP_MODE_SYNC). A successful operation returns the number of
 * packets consumed and outputs a new packet handle for each outputted packet.
 * Outputted packets contain IPSEC result metadata (odp_ipsec_packet_result_t),
 * which should be checked for transformation errors, etc. Outputted packets
 * with error status have undefined content, except that in case of MTU error
 * the original input packet data is returned. The operation does not modify
 * packets that it does not consume. It cannot consume all input packets if
 * 'num_out' is smaller than 'num_in'.
 *
 * Packet context pointer and user area content are copied from input to output
 * packets. Output packets are allocated from the same pool(s) as input packets.
 *
 * When outbound IP fragmentation offload is enabled, the number of outputted
 * packets may be greater than the number of input packets.
 *
 * Each input packet must have a valid value for these metadata (other metadata
 * is ignored):
 * - L3 offset: Offset to the first byte of the (outmost) IP header
 * - L4 offset: Offset to the L4 header if L4 checksum offload is requested
 *
 * Additionally, input IP packet length (odp_packet_len() minus
 * odp_packet_l3_offset()) must match values in protocol headers. Otherwise
 * results are undefined.
 *
 * Packets are processed in the input order. Packet order is maintained from
 * input 'pkt' array to output 'pkt' array. Packet order is not guaranteed
 * between calling threads.
 *
 * The operation does packet transformation according to IPSEC standards (see
 * e.g. RFC 4302 and 4303). Resulting packets are well formed IP packets
 * with IPSEC, etc headers constructed according to the standards. The amount
 * and content of packet data before the IP header is undefined. Use outbound
 * operation parameters to specify the amount of TFC padding appended to
 * the packet during IPSEC transformation. Options can be used also to create
 * TFC dummy packets. Packet data content is ignored in tunnel mode TFC dummy
 * packet creation as tfc_pad_len option defines solely the packet length.
 * In all other cases, payload length for the IPSEC transformation is specified
 * by odp_packet_len() minus odp_packet_l3_offset() plus tfc_pad_len option.
 *
 * Each successfully transformed packet has a valid value for these metadata:
 * - L3 offset: Offset to the first byte of the (outmost) IP header
 *
 * @param          pkt_in   Packets to be processed
 * @param          num_in   Number of packets to be processed
 * @param[out]     pkt_out  Packet handle array for resulting packets
 * @param[in, out] num_out  Number of resulting packets. Application sets this
 *                          to 'pkt_out' array size. A successful operation sets
 *                          this to the number of outputted packets
 *                          (1 ... num_out).
 * @param          param    Outbound operation parameters
 *
 * @return Number of input packets consumed (0 ... num_in)
 * @retval <0     On failure
 *
 * @see odp_packet_user_ptr(), odp_packet_user_area(), odp_packet_l3_offset()
 */
int odp_ipsec_out(const odp_packet_t pkt_in[], int num_in,
		  odp_packet_t pkt_out[], int *num_out,
		  const odp_ipsec_out_param_t *param);

/**
 * Inbound asynchronous IPSEC operation
 *
 * This operation does inbound IPSEC processing in asynchronous mode. It
 * processes packets otherwise identically to odp_ipsec_in(), but outputs
 * resulting packets as ODP_EVENT_PACKET events (with ODP_EVENT_PACKET_IPSEC
 * subtype). The following ordering considerations apply to the events.
 *
 * Asynchronous mode maintains packet order per SA when application calls the
 * operation within an ordered or atomic scheduler context of the same queue.
 * Resulting events for the same SA are enqueued in order. Packet order per SA
 * at a destination queue is the same as if application would have enqueued
 * packets there with odp_queue_enq_multi().
 *
 * Packet order is also maintained when application otherwise guarantees
 * (e.g. using locks) that the operation is not called simultaneously from
 * multiple threads for the same SA(s).
 *
 * Logically, packet processing (e.g. sequence number check) happens in the
 * output order as defined above.
 *
 * The function may be used also in inline processing mode, e.g. for IPSEC
 * packets for which inline processing is not possible. Packets for the same SA
 * may be processed simultaneously in both modes (initiated by this function
 * and inline operation).
 *
 * Post-processing may be required after the reception of an IPsec packet
 * event to complete IPsec processing for the packet. The post-processing
 * happens in the odp_ipsec_result() function that must be called at least
 * once before packet data or metadata (other than packet type and subtype)
 * may be accessed.
 *
 * If reassembly is attempted but fails, the result packet delivered to the
 * application will have reassembly status as ODP_PACKET_REASS_INCOMPLETE and
 * will not have ODP_EVENT_PACKET_IPSEC subtype. In that case, the application
 * can call odp_packet_reass_partial_state() to get fragments of the packet. The
 * fragments will have subtype as ODP_EVENT_PACKET_IPSEC and the application
 * must call odp_ipsec_result() for such a fragment before accessing its packet
 * data.
 *
 * @param          pkt      Packets to be processed
 * @param          num      Number of packets to be processed
 * @param          param    Inbound operation parameters
 *
 * @return Number of input packets consumed (0 ... num)
 * @retval <0     On failure
 *
 * @see odp_ipsec_in(), odp_ipsec_result()
 */
int odp_ipsec_in_enq(const odp_packet_t pkt[], int num,
		     const odp_ipsec_in_param_t *param);

/**
 * Outbound asynchronous IPSEC operation
 *
 * This operation does outbound IPSEC processing in asynchronous mode. It
 * processes packets otherwise identically to odp_ipsec_out(), but outputs
 * resulting packets as ODP_EVENT_PACKET events (with ODP_EVENT_PACKET_IPSEC
 * subtype). The following ordering considerations apply to the events.
 *
 * Asynchronous mode maintains packet order per SA when application calls the
 * operation within an ordered or atomic scheduler context of the same queue.
 * Resulting events for the same SA are enqueued in order. Packet order per SA
 * at a destination queue is the same as if application would have enqueued
 * packets there with odp_queue_enq_multi().
 *
 * Packet order is also maintained when application otherwise guarantees
 * (e.g. using locks) that the operation is not called simultaneously from
 * multiple threads for the same SA(s).
 *
 * Logically, packet processing (e.g. sequence number assignment) happens in the
 * output order as defined above.
 *
 * The function may be used also in inline processing mode, e.g. for IPSEC
 * packets for which inline processing is not possible.
 *
 * Post-processing may be required after the reception of an IPsec packet
 * event to complete IPsec processing for the packet. The post-processing
 * happens in the odp_ipsec_result() function that must be called at least
 * once before packet data or metadata (other than packet type and subtype)
 * may be accessed.
 *
 * @param          pkt      Packets to be processed
 * @param          num      Number of packets to be processed
 * @param          param    Outbound operation parameters
 *
 * @return Number of input packets consumed (0 ... num)
 * @retval <0     On failure
 *
 * @see odp_ipsec_out(), odp_ipsec_result()
 */
int odp_ipsec_out_enq(const odp_packet_t pkt[], int num,
		      const odp_ipsec_out_param_t *param);

/**
 * Outbound inline IPSEC operation
 *
 * This operation does outbound inline IPSEC processing for the packets. It's
 * otherwise identical to odp_ipsec_out_enq(), but outputs all successfully
 * transformed packets to the specified output interface (or tm_queue), instead of
 * generating events for those.
 *
 * Inline operation parameters are defined per packet. The array of parameters
 * must have 'num' elements and is pointed to by 'inline_param'.
 *
 * @param          pkt           Packets to be processed
 * @param          num           Number of packets to be processed
 * @param          param         Outbound operation parameters
 * @param          inline_param  Outbound inline operation specific parameters
 *
 * @return Number of packets consumed (0 ... num)
 * @retval <0     On failure
 *
 * @see odp_ipsec_out_enq()
 */
int odp_ipsec_out_inline(const odp_packet_t pkt[], int num,
			 const odp_ipsec_out_param_t *param,
			 const odp_ipsec_out_inline_param_t *inline_param);

/**
 * Convert IPSEC processed packet event to packet handle
 *
 * Get packet handle to an IPSEC processed packet event. Event subtype must be
 * ODP_EVENT_IPSEC_PACKET. IPSEC operation results can be examined with
 * odp_ipsec_result().
 *
 * @param ev       Event handle
 *
 * @return Packet handle
 *
 * @see odp_event_subtype(), odp_ipsec_result()
 */
odp_packet_t odp_ipsec_packet_from_event(odp_event_t ev);

/**
 * Convert IPSEC processed packet handle to event
 *
 * The packet handle must be an output of an IPSEC operation.
 *
 * @param pkt      Packet handle from IPSEC operation
 *
 * @return Event handle
 */
odp_event_t odp_ipsec_packet_to_event(odp_packet_t pkt);

/**
 * Get IPSEC operation results from an IPSEC processed packet
 *
 * Successful IPSEC operations of all types (SYNC, ASYNC and INLINE) produce
 * packets which contain IPSEC result metadata. This function copies the
 * operation results from an IPSEC processed packet. Event subtype of this kind
 * of packet is ODP_EVENT_PACKET_IPSEC. Results are undefined if a non-IPSEC
 * processed packet is passed as input.
 *
 * Some packet API operations output a new packet handle
 * (e.g. odp_packet_concat()). IPSEC metadata remain valid as long as the packet
 * handle is not changed from the original (output of e.g. odp_ipsec_in() or
 * odp_ipsec_packet_from_event() call) IPSEC processed packet handle.
 *
 * @param[out]    result  Pointer to operation result for output
 * @param         packet  An IPSEC processed packet (ODP_EVENT_PACKET_IPSEC)
 *
 * @retval  0     On success
 * @retval <0     On failure
 *
 * @see odp_ipsec_in(), odp_ipsec_in_enq(), odp_ipsec_out(),
 *      odp_ipsec_out_enq(), odp_ipsec_packet_from_event()
 */
int odp_ipsec_result(odp_ipsec_packet_result_t *result, odp_packet_t packet);

/**
 * Get IPSEC status information from an ODP_EVENT_IPSEC_STATUS event
 *
 * Copies IPSEC status information from an event. The event must be of
 * type ODP_EVENT_IPSEC_STATUS.
 *
 * @param[out]    status  Pointer to status information structure for output.
 * @param         event   An ODP_EVENT_IPSEC_STATUS event
 *
 * @retval  0     On success
 * @retval <0     On failure
 *
 * @see odp_ipsec_sa_disable()
 */
int odp_ipsec_status(odp_ipsec_status_t *status, odp_event_t event);

/**
 * IPSEC test API for modifying internal state of an SA.
 *
 * This function is not meant to be used by normal applications but by special
 * test applications that test or debug the operation of the underlying ODP
 * implementation. Calling this function may degrade the performance of the
 * calling thread, other threads or the IPSEC implementation in general.
 *
 * Calling this function for an SA at the same time when the SA is used for
 * processing traffic or when the SA is being modified through other parts
 * of IPSEC API may result in undefined behaviour.
 *
 * SA state update through this function may not be supported by all ODP
 * implementations, ODP instances or SA instances or at every moment. This
 * function may return failure for unspecified reasons even when the capability
 * call indicated support for updating a particular parameter and previous
 * similar calls succeeded.
 *
 * @param          sa            IPSEC SA to be updated
 * @param          op            Specifies operation to be performed
 * @param          param         Pointer to IPSEC TEST SA param structure to be
 *                               used for the operation
 *
 * @return 0      On success
 * @retval <0     On failure
 */
int odp_ipsec_test_sa_update(odp_ipsec_sa_t sa,
			     odp_ipsec_test_sa_operation_t op,
			     const odp_ipsec_test_sa_param_t *param);

/**
 * Update MTU for outbound IP fragmentation
 *
 * When IP fragmentation offload is enabled, the SA is created with an MTU.
 * This call may be used to update MTU at any time. MTU updates are not
 * expected to happen very frequently.
 *
 * @param sa      IPSEC SA to be updated
 * @param mtu     The new MTU value
 *
 * @retval 0      On success
 * @retval <0     On failure
 */
int odp_ipsec_sa_mtu_update(odp_ipsec_sa_t sa, uint32_t mtu);

/**
 * Get user defined SA context pointer
 *
 * @param sa      IPSEC SA handle
 *
 * @return User defined SA context pointer value
 * @retval NULL   On failure
 */
void *odp_ipsec_sa_context(odp_ipsec_sa_t sa);

/**
 * Print global IPSEC configuration info
 *
 * Print implementation-defined information about the global IPSEC
 * configuration.
 */
void odp_ipsec_print(void);

/**
 * Print IPSEC SA info
 *
 * @param sa      SA handle
 *
 * Print implementation-defined IPSEC SA debug information to the ODP log.
 */
void odp_ipsec_sa_print(odp_ipsec_sa_t sa);

/**
 * Get IPSEC stats for the IPSEC SA handle
 *
 * @param          sa       IPSEC SA handle
 * @param[out]     stats    Stats output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_ipsec_stats(odp_ipsec_sa_t sa, odp_ipsec_stats_t *stats);

/**
 * Get IPSEC stats for multiple IPSEC SA handles
 *
 * @param          sa       Array of IPSEC SA handles
 * @param[out]     stats    Stats array for output
 * @param          num      Number of SA handles
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_ipsec_stats_multi(odp_ipsec_sa_t sa[], odp_ipsec_stats_t stats[], int num);

/**
 * Retrieve information about an IPSEC SA
 *
 * The cipher and auth key data(including key extra) will not be exposed and
 * the corresponding pointers will be set to NULL. The IP address pointers
 * will point to the corresponding buffers available in the SA info structure.
 *
 * The user defined SA context pointer is an opaque field and hence the value
 * provided during the SA creation will be returned.
 *
 * @param      sa       The IPSEC SA for which to retrieve information
 * @param[out] sa_info  Pointer to caller allocated SA info structure to be
 *                      filled in
 *
 * @retval 0            On success
 * @retval <0           On failure
 **/
int odp_ipsec_sa_info(odp_ipsec_sa_t sa, odp_ipsec_sa_info_t *sa_info);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
