/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2020-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Packet IO
 */

#ifndef ODP_API_SPEC_PACKET_IO_H_
#define ODP_API_SPEC_PACKET_IO_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/classification.h>
#include <odp/api/packet_types.h>
#include <odp/api/packet_io_stats.h>
#include <odp/api/packet_io_types.h>
#include <odp/api/queue_types.h>
#include <odp/api/reassembly.h>
#include <odp/api/time.h>

/** @defgroup odp_packet_io ODP PACKET IO
 *  Packet IO interfaces.
 *
 * Packet IO is the Ingress and Egress interface to ODP processing. It
 * allows manipulation of the interface for setting such attributes as
 * number of queues, MAC address etc.
 * Pktio is usually followed by the classifier and a default class COS
 * can be set so that the scheduler may distribute flows. The interface
 * may be used directly in polled mode with odp_pktin_recv() and
 * odp_pktout_send().
 * Diagnostic messages can be enhanced by using odp_pktio_to_u64 which
 * will generate a printable reference for a pktio handle for use with
 * the logging.
 *  @{
 */

/**
 * Open a packet IO interface
 *
 * An ODP program can open a single packet IO interface per device, attempts
 * to open an already open device will fail, returning ODP_PKTIO_INVALID. Use
 * odp_pktio_lookup() to obtain a handle to an already open device. Packet IO
 * parameters provide interface level configuration options.
 *
 * Use odp_pktio_param_init() to initialize packet IO parameters into their
 * default values. Default values are also used when 'param' pointer is NULL.
 *
 * Packet input queue configuration must be setup with
 * odp_pktin_queue_config() before odp_pktio_start() is called. When packet
 * input mode is ODP_PKTIN_MODE_DISABLED, odp_pktin_queue_config() call is
 * optional and will ignore all parameters.
 *
 * Packet output queue configuration must be setup with
 * odp_pktout_queue_config() before odp_pktio_start() is called. When packet
 * output mode is ODP_PKTOUT_MODE_DISABLED or ODP_PKTOUT_MODE_TM,
 * odp_pktout_queue_config() call is optional and will ignore all parameters.
 *
 * Advanced packet IO interface offload features and options can be setup with
 * odp_pktio_config() before the interface is started. These features include e.g.
 * checksum, segmentation (LSO), reassembly and inline IPSEC offloads. When
 * odp_pktio_config() is not used, the interface is started with the default
 * values of odp_pktio_config_t.
 *
 * Packet receive and transmit on the interface is enabled with a call to
 * odp_pktio_start(). If not specified otherwise, any interface level
 * configuration must not be changed when the interface is active (between start
 * and stop calls).
 *
 * In summary, a typical pktio interface setup sequence is ...
 *   * odp_pktio_open()
 *   * odp_pktin_queue_config()
 *   * odp_pktout_queue_config()
 *   * [optionally] odp_pktio_config()
 *   * odp_pktio_start()
 *
 * ... and tear down sequence is:
 *   * odp_pktio_stop()
 *   * odp_pktio_close()
 *
 * @param name   Packet IO device name
 * @param pool   Default pool from which to allocate storage for packets
 *               received over this interface, must be of type ODP_POOL_PACKET
 * @param param  Packet IO parameters. Uses defaults when NULL.
 *
 * @return Packet IO handle
 * @retval ODP_PKTIO_INVALID on failure
 *
 * @note The device name "loop" is a reserved name for a loopback device used
 *	 for testing purposes.
 *
 * @note Packets arriving via this interface assigned to a CoS by the
 *	 classifier are received into the pool associated with that CoS. This
 *	 will occur either because this pktio is assigned a default CoS via
 *	 the odp_pktio_default_cos_set() routine, or because a matching PMR
 *	 assigned the packet to a specific CoS. The default pool specified
 *	 here is applicable only for those packets that are not assigned to a
 *	 more specific CoS that specifies another pool.
 *
 * @see odp_pktio_start(), odp_pktio_stop(), odp_pktio_close()
 */
odp_pktio_t odp_pktio_open(const char *name, odp_pool_t pool,
			   const odp_pktio_param_t *param);

/**
 * Query packet IO interface capabilities
 *
 * Outputs packet IO interface capabilities on success.
 *
 * @param      pktio  Packet IO handle
 * @param[out] capa   Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_pktio_capability(odp_pktio_t pktio, odp_pktio_capability_t *capa);

/**
 * Maximum packet IO interface index
 *
 * Return the maximum packet IO interface index. Interface indexes
 * (e.g. returned by odp_pktio_index()) range from zero to this maximum value.
 *
 * @return Maximum packet IO interface index
 */
unsigned int odp_pktio_max_index(void);

/**
 * Configure packet IO interface options
 *
 * Select interface level configuration options before the interface is
 * activated (before odp_pktio_start() call). This step is optional in pktio
 * interface setup sequence. Use odp_pktio_capability() to query configuration
 * capabilities. Use odp_pktio_config_init() to initialize
 * configuration options into their default values. Default values are used
 * when 'config' pointer is NULL.
 *
 * @param pktio    Packet IO handle
 * @param config   Packet IO interface configuration. Uses defaults
 *                 when NULL.
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_pktio_config(odp_pktio_t pktio, const odp_pktio_config_t *config);

/**
 * Configure packet input queues
 *
 * Setup a number of packet input queues and configure those. The maximum number
 * of queues is platform dependent and can be queried with
 * odp_pktio_capability(). Use odp_pktin_queue_param_init() to initialize
 * parameters into their default values. Default values are also used when
 * 'param' pointer is NULL.
 *
 * Queue handles for input queues can be requested with odp_pktin_queue() or
 * odp_pktin_event_queue() after this call. All requested queues are setup on
 * success, no queues are setup on failure. Each call reconfigures input queues
 * and may invalidate all previous queue handles.
 *
 * @param pktio    Packet IO handle
 * @param param    Packet input queue configuration parameters. Uses defaults
 *                 when NULL.
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_pktio_capability(), odp_pktin_queue(), odp_pktin_event_queue()
 */
int odp_pktin_queue_config(odp_pktio_t pktio,
			   const odp_pktin_queue_param_t *param);

/**
 * Configure packet output queues
 *
 * Setup a number of packet output queues and configure those. The maximum
 * number of queues is platform dependent and can be queried with
 * odp_pktio_capability(). Use odp_pktout_queue_param_init() to initialize
 * parameters into their default values. Default values are also used when
 * 'param' pointer is NULL.
 *
 * Queue handles for output queues can be requested with odp_pktout_queue() or
 * odp_pktout_event_queue() after this call. All requested queues are setup on
 * success, no queues are setup on failure. Each call reconfigures output queues
 * and may invalidate all previous queue handles.
 *
 * @param pktio    Packet IO handle
 * @param param    Packet output queue configuration parameters. Uses defaults
 *                 when NULL.
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_pktio_capability(), odp_pktout_queue(), odp_pktout_event_queue()
 */
int odp_pktout_queue_config(odp_pktio_t pktio,
			    const odp_pktout_queue_param_t *param);

/**
 * Event queues for packet input
 *
 * Returns the number of input queues configured for the interface in
 * ODP_PKTIN_MODE_QUEUE and ODP_PKTIN_MODE_SCHED modes. Outputs up to 'num'
 * queue handles when the 'queues' array pointer is not NULL. If return value is
 * larger than 'num', there are more queues than the function was allowed to
 * output. If return value (N) is less than 'num', only queues[0 ... N-1] have
 * been written.
 *
 * In addition to packet input, application and other parts of ODP (e.g. timer)
 * may enqueue events into these queues. Depending on the queue mode, application
 * uses either odp_queue_deq() or odp_schedule() (or variants of those) to receive
 * packets and other events from these queues.
 *
 * @param      pktio    Packet IO handle
 * @param[out] queues   Points to an array of queue handles for output
 * @param      num      Maximum number of queue handles to output
 *
 * @return Number of packet input queues
 * @retval <0 on failure
 */
int odp_pktin_event_queue(odp_pktio_t pktio, odp_queue_t queues[], int num);

/**
 * Direct packet input queues
 *
 * Returns the number of input queues configured for the interface in
 * ODP_PKTIN_MODE_DIRECT mode. Outputs up to 'num' queue handles when the
 * 'queues' array pointer is not NULL. If return value is larger than 'num',
 * there are more queues than the function was allowed to output. If return
 * value (N) is less than 'num', only queues[0 ... N-1] have been written.
 *
 * Packets from these queues are received with odp_pktin_recv().
 *
 * @param      pktio    Packet IO handle
 * @param[out] queues   Points to an array of queue handles for output
 * @param      num      Maximum number of queue handles to output
 *
 * @return Number of packet input queues
 * @retval <0 on failure
 */
int odp_pktin_queue(odp_pktio_t pktio, odp_pktin_queue_t queues[], int num);

/**
 * Event queues for packet output
 *
 * Returns the number of output queues configured for the interface in
 * ODP_PKTOUT_MODE_QUEUE. Outputs up to 'num' queue handles when the
 * 'queues' array pointer is not NULL. If return value is larger than 'num',
 * there are more queues than the function was allowed to output. If return
 * value (N) is less than 'num', only queues[0 ... N-1] have been written.
 *
 * Packets are enqueued to these queues with odp_queue_enq() or
 * odp_queue_enq_multi(). Behaviour is undefined if other events than packets
 * are enqueued. Application cannot dequeue from these queues.
 *
 * @param      pktio    Packet IO handle
 * @param[out] queues   Points to an array of queue handles for output
 * @param      num      Maximum number of queue handles to output
 *
 * @return Number of packet output queues
 * @retval <0 on failure
 */
int odp_pktout_event_queue(odp_pktio_t pktio, odp_queue_t queues[], int num);

/**
 * Direct packet output queues
 *
 * Returns the number of output queues configured for the interface in
 * ODP_PKTOUT_MODE_DIRECT mode. Outputs up to 'num' queue handles when the
 * 'queues' array pointer is not NULL. If return value is larger than 'num',
 * there are more queues than the function was allowed to output. If return
 * value (N) is less than 'num', only queues[0 ... N-1] have been written.
 *
 * Packets are sent to these queues with odp_pktout_send().
 *
 * @param      pktio    Packet IO handle
 * @param[out] queues   Points to an array of queue handles for output
 * @param      num      Maximum number of queue handles to output
 *
 * @return Number of packet output queues
 * @retval <0 on failure
 */
int odp_pktout_queue(odp_pktio_t pktio, odp_pktout_queue_t queues[], int num);

/**
 * Start packet receive and transmit
 *
 * Activate packet receive and transmit on a previously opened or stopped
 * interface. The interface can be stopped with a call to odp_pktio_stop().
 *
 * @param pktio  Packet IO handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_pktio_open(), odp_pktio_stop()
 */
int odp_pktio_start(odp_pktio_t pktio);

/**
 * Stop packet receive and transmit
 *
 * Stop packet receive and transmit on a previously started interface. New
 * packets are not received from or transmitted to the network. Packets already
 * received from the network may be still available from interface and
 * application can receive those normally. New packets may not be accepted for
 * transmit. Packets already stored for transmit are not freed. A following
 * odp_packet_start() call restarts packet receive and transmit.
 *
 * @param pktio  Packet IO handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_pktio_start(), odp_pktio_close()
 */
int odp_pktio_stop(odp_pktio_t pktio);

/**
 * Close a packet IO interface
 *
 * Close a stopped packet IO interface. This call frees all remaining packets
 * stored in pktio receive and transmit side buffers. The pktio is destroyed
 * and the handle must not be used for other calls. After a successful call,
 * the same pktio device can be opened again with a odp_pktio_open() call.
 *
 * @param pktio  Packet IO handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_pktio_stop(), odp_pktio_open()
 */
int odp_pktio_close(odp_pktio_t pktio);

/**
 * Return a packet IO handle for an already open device
 *
 * @param name   Packet IO device name
 *
 * @return Packet IO handle
 * @retval ODP_PKTIO_INVALID on failure
 */
odp_pktio_t odp_pktio_lookup(const char *name);

/**
 * Receive packets directly from an interface input queue
 *
 * Receives up to 'num' packets from the pktio interface input queue. Returns
 * the number of packets received.
 *
 * When input queue parameter 'op_mode' has been set to ODP_PKTIO_OP_MT_UNSAFE,
 * the operation is optimized for single thread operation per queue and the same
 * queue must not be accessed simultaneously from multiple threads.
 *
 * @param      queue      Packet input queue handle for receiving packets
 * @param[out] packets[]  Packet handle array for output of received packets
 * @param      num        Maximum number of packets to receive
 *
 * @return Number of packets received
 * @retval <0 on failure
 *
 * @see odp_pktin_queue()
 */
int odp_pktin_recv(odp_pktin_queue_t queue, odp_packet_t packets[], int num);

/**
 * Receive packets directly from an interface input queue with timeout
 *
 * Provides the same functionality as odp_pktin_recv(), except that waits if
 * there are no packets available. Wait time is specified by the 'wait'
 * parameter.
 *
 * @param      queue      Packet input queue handle for receiving packets
 * @param[out] packets[]  Packet handle array for output of received packets
 * @param      num        Maximum number of packets to receive
 * @param      wait       Wait time specified as as follows:
 *                        * ODP_PKTIN_NO_WAIT: Do not wait
 *                        * Other values specify the minimum time to wait.
 *                          Use odp_pktin_wait_time() to convert nanoseconds
 *                          to a valid parameter value. Wait time may be
 *                          rounded up a small, platform specific amount.
 *
 * @return Number of packets received
 * @retval <0 on failure
 */
int odp_pktin_recv_tmo(odp_pktin_queue_t queue, odp_packet_t packets[],
		       int num, uint64_t wait);

/**
 * Receive packets directly from multiple interface input queues with timeout
 *
 * Receives up to 'num' packets from one of the specified pktio interface input
 * queues. The index of the source queue is stored into 'from' output
 * parameter. If there are no packets available on any of the queues, waits for
 * packets depending on 'wait' parameter value. Returns the number of packets
 * received.
 *
 * When an input queue has been configured with 'op_mode' value
 * ODP_PKTIO_OP_MT_UNSAFE, the operation is optimized for single thread
 * operation and the same queue must not be accessed simultaneously from
 * multiple threads.
 *
 * It is implementation specific in which order the queues are checked for
 * packets. Application may improve fairness of queue service levels by
 * circulating queue handles between consecutive calls (e.g. [q0, q1, q2, q3] ->
 * [q1, q2, q3, q0] -> [q2, q3, ...).
 *
 * @param      queues[]   Packet input queue handles for receiving packets
 * @param      num_q      Number of input queues
 * @param[out] from       Pointer for output of the source queue index. Ignored
 *                        when NULL.
 * @param[out] packets[]  Packet handle array for output of received packets
 * @param      num        Maximum number of packets to receive
 * @param      wait       Wait time specified as as follows:
 *                        * ODP_PKTIN_NO_WAIT: Do not wait
 *                        * Other values specify the minimum time to wait.
 *                          Use odp_pktin_wait_time() to convert nanoseconds
 *                          to a valid parameter value. Wait time may be
 *                          rounded up a small, platform specific amount.
 *
 * @return Number of packets received
 * @retval <0 on failure
 */
int odp_pktin_recv_mq_tmo(const odp_pktin_queue_t queues[], uint32_t num_q, uint32_t *from,
			  odp_packet_t packets[], int num, uint64_t wait);

/**
 * Packet input wait time
 *
 * Converts nanoseconds to wait time values for packet input functions.
 *
 * @param nsec   Minimum number of nanoseconds to wait
 *
 * @return Wait parameter value for packet input functions
 */
uint64_t odp_pktin_wait_time(uint64_t nsec);

/**
 * Send packets directly to an interface output queue
 *
 * Sends out a number of packets to the interface output queue. When
 * output queue parameter 'op_mode' has been set to ODP_PKTIO_OP_MT_UNSAFE,
 * the operation is optimized for single thread operation per queue and the same
 * queue must not be accessed simultaneously from multiple threads.
 *
 * A successful call returns the actual number of packets accepted for transmit. If return value
 * is less than 'num', the remaining packets at the end of packets[] array are not consumed,
 * and the caller has to take care of them. Transmitted packets are freed back into their
 * originating pools by default. If interface supports #ODP_PACKET_FREE_CTRL_DONT_FREE
 * option and it is set (odp_packet_free_ctrl_set()) in a packet, the packet is not freed
 * but application owns it again after its transmit is complete. Application may use
 * odp_packet_tx_compl_request() to request an indication when transmit of a packet is complete.
 *
 * Entire packet data is sent out (odp_packet_len() bytes of data, starting from
 * odp_packet_data()). All other packet metadata is ignored unless otherwise
 * specified e.g. for protocol offload purposes. Link protocol specific frame
 * checksum and padding are added to frames before transmission.
 *
 * @param queue        Packet output queue handle for sending packets
 * @param packets[]    Array of packets to send
 * @param num          Number of packets to send
 *
 * @return Number of packets accepted for transmit
 * @retval <0 on failure
 */
int odp_pktout_send(odp_pktout_queue_t queue, const odp_packet_t packets[],
		    int num);

/**
 * Initialize LSO profile parameters
 *
 * Initialize an odp_lso_profile_param_t to its default values for all fields.
 *
 * @param param Address of the odp_lso_profile_param_t to be initialized
 */
void odp_lso_profile_param_init(odp_lso_profile_param_t *param);

/**
 * Create LSO profile
 *
 * LSO profile defines the set of segmentation operations to be performed to a packet. LSO profiles
 * are created before the packet IO interface is started (after odp_pktio_config() and before
 * odp_pktio_start()).
 *
 * See odp_lso_capability_t for maximum number of profiles supported and other LSO capabilities.
 *
 * @param pktio   Packet IO interface which is used with this LSO profile
 * @param param   LSO profile parameters
 *
 * @return LSO profile handle
 * @retval ODP_LSO_PROFILE_INVALID on failure
 */
odp_lso_profile_t odp_lso_profile_create(odp_pktio_t pktio, const odp_lso_profile_param_t *param);

/**
 * Destroy LSO profile
 *
 * LSO profiles can be destroyed only when the packet IO interface is not active (i.e. after it
 * has been stopped).
 *
 * @param lso_profile   LSO profile to be destroyed
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_lso_profile_destroy(odp_lso_profile_t lso_profile);

/**
 * Send packets with segmentation offload
 *
 * Like odp_pktout_send(), but splits a packet payload into 'max_payload_len' or smaller segments
 * during output. Packet headers (before 'payload_offset') are copied into each segment and
 * automatically modified before transmission. Header updates are based on segmentation protocol
 * selection (odp_lso_profile_param_t::lso_proto) in LSO profile. Header checksums are updated
 * after modifications. L3/L4 header modifications (see e.g. ODP_LSO_PROTO_TCP_IPV4) require that
 * L3/L4 layer offsets in the packet are valid (see e.g. odp_packet_l3_offset()).
 *
 * In addition, custom field updates may be used to cover unsupported or proprietary protocols.
 * Custom fields must not overlap with each other and can be used only when ODP_LSO_PROTO_CUSTOM
 * is selected.
 *
 * Packets are processed and transmitted in the array order. Segments of each packet are transmitted
 * in ascending order.
 *
 * When all packets share the same LSO options, usage of 'lso_opt' parameter may improve
 * performance as a number of packet metadata writes/reads are avoided. Results are undefined if
 * 'lso_opt' is NULL and a packet misses LSO options.
 *
 * Packets with less than (or equal to) 'max_payload_len' payload bytes can be sent also, however
 * odp_pktout_send() should be more optimal for those than this function.
 *
 * Check LSO support level from packet IO capabilities (odp_pktio_capability_t).
 *
 * @param queue     Packet output queue handle
 * @param packet[]  Array of packets to be LSO processed and sent
 * @param num       Number of packets
 * @param lso_opt   When set, LSO options to be used for all packets. When NULL, LSO options are
 *                  read from each packet (see odp_packet_lso_request()).
 *
 * @return Number of packets successfully segmented (0 ... num)
 * @retval <0 on failure
 */
int odp_pktout_send_lso(odp_pktout_queue_t queue, const odp_packet_t packet[], int num,
			const odp_packet_lso_opt_t *lso_opt);

/**
 * Set promiscuous mode
 *
 * Enable or disable promiscuous mode on a packet IO interface. Use packet IO capability
 * odp_pktio_set_op_t::promisc_mode to check if an interface supports this operation.
 * When the operation is supported, promiscuous mode is disabled by default.
 *
 * @param pktio   Packet IO handle.
 * @param enable  1 to enable, 0 to disable.
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_pktio_promisc_mode_set(odp_pktio_t pktio, odp_bool_t enable);

/**
 * Determine if promiscuous mode is enabled for a packet IO interface.
 *
 * @param pktio  Packet IO handle.
 *
 * @retval  1 if promiscuous mode is enabled.
 * @retval  0 if promiscuous mode is disabled.
 * @retval <0 on failure
*/
int odp_pktio_promisc_mode(odp_pktio_t pktio);

/**
 * Maximum frame length at packet input
 *
 * Maximum frame length in bytes that the packet IO interface can receive.
 * For Ethernet, the frame length bytes start with MAC addresses and continue
 * to the end of the payload. So, Ethernet checksum, interpacket gap
 * and preamble bytes are excluded from the length.
 *
 * @param pktio  Packet IO handle.
 *
 * @return Maximum frame length at packet input
 * @retval 0 on failure
 */
uint32_t odp_pktin_maxlen(odp_pktio_t pktio);

/**
 * Maximum frame length at packet output
 *
 * Maximum frame length in bytes that the packet IO interface can transmit.
 * For Ethernet, the frame length bytes start with MAC addresses and continue
 * to the end of the payload. So, Ethernet checksum, interpacket gap
 * and preamble bytes are excluded from the length.
 *
 * @param pktio  Packet IO handle.
 *
 * @return Maximum frame length at packet output
 * @retval 0 on failure
 */
uint32_t odp_pktout_maxlen(odp_pktio_t pktio);

/**
 * Set maximum frame lengths
 *
 * Set the maximum frame lengths in bytes that the packet IO interface can
 * receive and transmit. For Ethernet, the frame length bytes start with MAC
 * addresses and continue to the end of the payload. So, Ethernet checksum,
 * interpacket gap, and preamble bytes are excluded from the lengths.
 *
 * Use odp_pktio_capability() to query interface capabilities. If setting
 * maximum frame length is only supported in input or output direction, the
 * parameter for the unsupported direction has to be set to zero. When
 * 'equal' flag in odp_pktio_capability_t::maxlen is set, the same maximum
 * frame length value has to be used for both input and output directions.
 *
 * @param pktio         Packet IO handle
 * @param maxlen_input  Maximum frame length at packet input
 * @param maxlen_output Maximum frame length at packet output
 *
 * @retval  0 on success
 * @retval <0 on failure
 *
 * @see odp_pktin_maxlen(), odp_pktout_maxlen()
 */
int odp_pktio_maxlen_set(odp_pktio_t pktio, uint32_t maxlen_input,
			 uint32_t maxlen_output);

/**
 * Get the default MAC address of a packet IO interface.
 *
 * @param	pktio     Packet IO handle
 * @param[out]	mac_addr  Output buffer (use ODP_PKTIO_MACADDR_MAXSIZE)
 * @param       size      Size of output buffer
 *
 * @return Number of bytes written (actual size of MAC address)
 * @retval <0 on failure
 */
int odp_pktio_mac_addr(odp_pktio_t pktio, void *mac_addr, int size);

/**
 * Set the default MAC address of a packet IO interface.
 *
 * Support of this operation on a packet IO interface is reported
 * through ‘mac_addr’ set operation capability.
 *
 * @param	pktio     Packet IO handle
 * @param	mac_addr  MAC address to be set as default address
 * @param	size      Size of the MAC address
 *
 * @return 0 on success
 * @retval <0 on failure
 */
int odp_pktio_mac_addr_set(odp_pktio_t pktio, const void *mac_addr,
			   int size);

/**
 * Setup per-port default class-of-service.
 *
 * @param pktio        Ingress port pktio handle.
 * @param default_cos  Class-of-service set to all packets arriving at this
 *                     ingress port. Use ODP_COS_INVALID to remove the default
 *                     CoS.
 *
 * @retval  0 on success
 * @retval <0 on failure
 *
 * @note The default_cos has to be unique per odp_pktio_t instance.
 */
int odp_pktio_default_cos_set(odp_pktio_t pktio, odp_cos_t default_cos);

/**
 * Setup per-port error class-of-service
 *
 * @param pktio      Ingress port pktio handle.
 * @param error_cos  class-of-service set to all packets arriving at this
 *                   ingress port that contain an error.
 *
 * @retval  0 on success
 * @retval <0 on failure
 *
 * @note Optional.
 */
int odp_pktio_error_cos_set(odp_pktio_t pktio, odp_cos_t error_cos);

/**
 * Setup per-port header offset
 *
 * @param pktio      Ingress port pktio handle.
 * @param offset     Number of bytes the classifier must skip.
 *
 * This option is input to packet input parser/classifier indicating
 * how many bytes of data should be skipped from start of packet,
 * before parsing starts. So this option effects all packet input
 * protocol identification and other offloads.
 *
 * @retval  0 on success
 * @retval <0 on failure
 *
 * @note Optional.
 */
int odp_pktio_skip_set(odp_pktio_t pktio, uint32_t offset);

/**
 * Specify per-port buffer headroom
 *
 * @param pktio     Ingress port pktio handle.
 * @param headroom  Number of bytes of space preceding packet data to reserve
 *                  for use as headroom. Must not exceed the implementation
 *                  defined ODP_PACKET_MAX_HEADROOM.
 *
 * @retval			0 on success
 * @retval			<0 on failure
 *
 * @note Optional.
 */
int odp_pktio_headroom_set(odp_pktio_t pktio, uint32_t headroom);

/**
 * Get pktio interface index
 *
 * @param pktio   Packet I/O handle
 *
 * @return        Packet interface index (0..odp_pktio_max_index())
 * @retval <0     On failure (e.g., handle not valid)
 */
int odp_pktio_index(odp_pktio_t pktio);

/**
 * Get printable value for an odp_pktio_t
 *
 * @param pktio   odp_pktio_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_pktio_t handle.
 */
uint64_t odp_pktio_to_u64(odp_pktio_t pktio);

/**
 * Initialize pktio params
 *
 * Initialize an odp_pktio_param_t to its default values for all fields
 *
 * @param param Address of the odp_pktio_param_t to be initialized
 */
void odp_pktio_param_init(odp_pktio_param_t *param);

/**
 * Initialize packet input queue parameters
 *
 * Initialize an odp_pktin_queue_param_t to its default values.
 *
 * @param param   Input queue parameter structure to be initialized
 */
void odp_pktin_queue_param_init(odp_pktin_queue_param_t *param);

/**
 * Initialize packet output queue parameters
 *
 * Initialize an odp_pktout_queue_param_t to its default values.
 *
 * @param param   Output queue parameter structure to be initialized
 */
void odp_pktout_queue_param_init(odp_pktout_queue_param_t *param);

/**
 * Initialize packet IO configuration options
 *
 * Initialize an odp_pktio_config_t to its default values.
 *
 * @param config  Packet IO interface configuration
 */
void odp_pktio_config_init(odp_pktio_config_t *config);

/**
 * Print pktio info to the console
 *
 * Print implementation-defined pktio debug information to the console.
 *
 * @param pktio	                Packet IO handle
 */
void odp_pktio_print(odp_pktio_t pktio);

/**
 * Determine pktio link is up or down for a packet IO interface.
 *
 * @param pktio Packet IO handle.
 *
 * @retval  ODP_PKTIO_LINK_STATUS_UP or ODP_PKTIO_LINK_STATUS_DOWN on success
 * @retval  ODP_PKTIO_LINK_STATUS_UNKNOWN on failure
*/
odp_pktio_link_status_t odp_pktio_link_status(odp_pktio_t pktio);

/**
 * Retrieve information about a pktio
 *
 * Fills in packet IO information structure with current parameter values.
 * May be called any time with a valid pktio handle. The call is not
 * synchronized with configuration changing calls. The application should
 * ensure that it does not simultaneously change the configuration and retrieve
 * it with this call. The call is not intended for fast path use. The info
 * structure is written only on success.
 *
 * @param      pktio   Packet IO handle
 * @param[out] info    Pointer to packet IO info struct for output
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktio_info(odp_pktio_t pktio, odp_pktio_info_t *info);

/**
 * Retrieve information about packet IO link status
 *
 * Fills in link information structure with the current link status values.
 * May be called any time with a valid pktio handle. The call is not intended
 * for fast path use. The info structure is written only on success.
 *
 * @param      pktio   Packet IO handle
 * @param[out] info    Pointer to packet IO link info struct for output
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktio_link_info(odp_pktio_t pktio, odp_pktio_link_info_t *info);

/**
 * Packet IO timestamp resolution in hertz
 *
 * This is the resolution of packet input and output timestamps using a packet
 * IO time source.
 *
 * @param      pktio   Packet IO handle
 *
 * @return Packet IO timestamp resolution in hertz
 * @retval 0 on failure
 */
uint64_t odp_pktio_ts_res(odp_pktio_t pktio);

/**
 * Convert nanoseconds to packet IO time
 *
 * Packet IO time source is used for timestamping incoming and outgoing packets.
 * This function is used to convert nanosecond time to packet input or output
 * timestamp time.
 *
 * @param      pktio   Packet IO handle
 * @param      ns      Time in nanoseconds
 *
 * @return Packet IO timestamp
 * @retval ODP_TIME_NULL on failure
 */
odp_time_t odp_pktio_ts_from_ns(odp_pktio_t pktio, uint64_t ns);

/**
 * Current packet IO time and global time
 *
 * Returns current packet IO time and optionally global time. The returned
 * global time is that of global time source, where as the packet IO time is of
 * packet IO time source that is used to timestamp incoming and outgoing
 * packets.
 *
 * @param      pktio        Packet IO handle
 * @param[out] ts_global    Pointer to odp_time_t for output or NULL.
 *                          On success, global timestamp will be taken at the
 *                          same point of time as packet IO time.
 *
 * @return Current packet IO time
 * @retval ODP_TIME_NULL on failure
 */
odp_time_t odp_pktio_time(odp_pktio_t pktio, odp_time_t *ts_global);

/**
 * Read last captured Tx timestamp of a packet if available and clear it for
 * next timestamp.
 *
 * @param      pktio   Packet IO handle
 * @param[out] ts      Pointer to odp_time_t for output
 *
 * @retval  0 on success
 * @retval >0 Timestamp not available either because none has been requested or
 *            the requested timestamp is not yet available. In case it is the
 *            latter, then retry again later for retrieving the timestamp.
 * @retval <0 on failure
 */
int odp_pktout_ts_read(odp_pktio_t pktio, odp_time_t *ts);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
