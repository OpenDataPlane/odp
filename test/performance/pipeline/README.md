# odp_pipeline

Configurable ODP pipeline tester. Takes a `libconfig` compatible configuration file and based on
the configuration builds an ODP application. Configuration is quite flexible, user can define e.g.
ODP worker cpu mappings, basic resources to be created, resource dependencies, input and output
handling for queues, etc. Actual event handling is done in "work" objects which can be chained and
attached to queue input and output handling. Currently, a few example work objects are provided,
more can be easily added as required. This enables the tester to be built as e.g. a packet
generator, an L2 forwarder or something resembling an actual telecom application.

## Configuration structure

The passed configuration is divided into domains which the tester parses at the beginning.
The domains follow ODP modules (in addition to tester specific domains), e.g. there is a
domain for configuring queues, one for packet I/Os etc. Currently supported domains:

  - classification
  - cpumap
  - crypto
  - dma
  - flows
  - pktios
  - pools
  - queues
  - scheduler
  - stash
  - timers
  - workers

The domains can appear in the configuration file in any order, domain parser plugins are evaluated
in a predetermined order, set by developer. This defines an ordering for example between pools and
packet I/Os: packet I/Os require pools so pools are deployed first and packet I/O parser can assume
that configured pool resources will be available during packet I/O deployment. Resources are always
named and queried using the configured names (e.g. packet I/O resources can query named pool
resources).

Tester will abort if a name lookup error is encountered as this typically represents a fatal
configuration error and should be fixed by the user.

Some domains support entry templates, where a single configuration entry can be defined as a
template which is instantiated a given number of times. This can save a considerable amount of
time typing in case application requires e.g. hundreds of queues to be configured.

Domain resource parameterization follows the related ODP module resource creation parameters and
their defaults. E.g. within classification domain, `cos` and `pmr` configuration end up filling
`odp_cls_cos_param_t` and `odp_pmr_param_t` structures. Some parameters may not be configurable
depending on the domain either because infeasibility to support certain logic or support simply not
existing yet but might in the future. More details in the next section.

A few examples showcasing how one could configure the pipeline:

[pipeline_example1](pipeline_example1)
[pipeline_example2](pipeline_example2)

## Domains

### Classification

- name in configuration file: `classification`
- type: group with nested lists `cos` and `pmr` of groups
- `cos` entries:
  - element: `template`
    - necessity: optional
    - type: integer
    - values: number of resources to be instantiated based on the template
  - element: `name`
    - necessity: required
    - type: string, max `ODP_COS_NAME_LEN`, or in case of a template, a list of name prefix string,
            initial index value integer and increment value integer, which will be concatenated to
            a string, max `ODP_COS_NAME_LEN`
  - element: `action`
    - necessity: optional
    - type: `string`
    - values: `"drop"`, `"enqueue"`, mapping to `odp_cos_action_t`
    - default: `odp_cls_cos_param_init()`
  - element: `default`
    - necessity: optional
    - type: string
    - values: packet I/O domain resource name to attach this CoS as default
  - element: `num_queues`
    - necessity: optional
    - type: integer
    - default: `odp_cls_cos_param_init()`
  - element: `queue`
    - necessity: required if `num_queues` == 1 and `action` == `"enqueue"`
    - type: string, max `ODP_QUEUE_NAME_LEN`, or in case of a template, a list of name prefix
            string, initial index value integer and increment value integer, which will be
            concatenated to a string, max `ODP_QUEUE_NAME_LEN`
    - values: queue domain resource name
  - element: `type`
    - necessity: optional
    - type: string
    - values: `"plain"`, `"schedule"`, mapping to `odp_queue_type_t`
    - default: `odp_queue_param_init()`
  - element: `hash_ipv4_udp`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_hash_proto_t` bitfield
    - default: `0`
  - element: `hash_ipv4_tcp`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_hash_proto_t` bitfield
    - default: `0`
  - element: `hash_ipv4`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_hash_proto_t` bitfield
    - default: `0`
  - element: `hash_ipv6_udp`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_hash_proto_t` bitfield
    - default: `0`
  - element: `hash_ipv6_tcp`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_hash_proto_t` bitfield
    - default: `0`
  - element: `hash_ipv6`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_hash_proto_t` bitfield
    - default: `0`
  - element: `pool`
    - necessity: required
    - type: string, max `ODP_POOL_NAME_LEN`
    - values: pool domain resource name
- `pmr` entries:
  - element: `template`
    - necessity: optional
    - type: integer
    - values: number of resources to be instantiated based on the template
  - element: `name`
    - necessity: required
    - type: string, max `ODP_COS_NAME_LEN`, or in case of a template, a list of name prefix string,
            initial index value integer and increment value integer, which will be concatenated to
            a string, max `ODP_COS_NAME_LEN`
  - element: `src_cos`
    - necessity: required
    - type: string, max `ODP_COS_NAME_LEN`, or in case of a template, a list of name prefix string,
            initial index value integer and increment value integer, which will be concatenated to
            a string, max `ODP_COS_NAME_LEN`
    - values: classification domain CoS resource name
  - element: `dst_cos`
    - necessity: required
    - type: string, max `ODP_COS_NAME_LEN`, or in case of a template, a list of name prefix string,
            initial index value integer and increment value integer, which will be concatenated to
            a string, max `ODP_COS_NAME_LEN`
    - values: classification domain CoS resource name
  - element: `term`
    - necessity: required
    - type: string
    - values: `"len"`, `"eth_0"`, `"eth_x"`, `"vlan_0"`, `"vlan_x"`, `"vlan_pcp"`, `"dmac"`,
              `"ipproto"`, `"ip_dscp"`, `"udp_dport"`, `"tcp_dport"`, `"udp_sport"`, `"tcp_sport"`,
              `"sip_addr"`, `"dip_addr"`, `"sip6_addr"`, `"dip6_addr"`, `"ipsec_spi"`, `"ld_vni"`,
              `"custom_frame"`, `"custom_l3"`, `"sctp_sport"`, `"sctp_dport"`, mapping to
              `odp_cls_pmr_term_t`
  - element: `match_value`
    - necessity: required
    - type: byte value array, or in case of a template, a list of initial byte value array and
            increment value integer
  - element: `match_mask`
    - necessity: required
    - type: byte value array
  - element: `val_sz`
    - necessity: required
    - type: integer
  - element: `offset`
    - necessity: required if `term` == `"custom_frame"` or `"custom_l3"`
    - type: integer

### Cpumap

- name in configuration file: `cpumap`
- type: group
- `cpumap` entry:
  - element: `cpumask`
    - necessity: required
    - type: string
    - values: a CPU mask in a string format accepted by `odp_cpumask_to_str()`
  - element: `workers`
    - necessity: required
    - type: string array
    - values: worker resource names in order they are to be launched to the cores set in `cpumask`

### Crypto

- name in configuration file: `crypto`
- type: list of groups
- `crypto` entries:
  - element: `name`
    - necessity: required
    - type: string
  - element: `op`
    - necessity: required
    - type: string
    - values: `"encode"`, `"decode"`, mapping to `odp_crypto_op_t`
    - default: `odp_crypto_session_param_init()`
  - element: `cipher_alg`
    - necessity: optional
    - type: string
    - values: `"null"`, `"des"`, `"3des_cbc"`, `"3des_ecb"`, `"aes_cbc"`, `"aes_ctr"`, `"aes_ecb"`,
              `"aes_cfb128"`, `"aes_xts"`, `"aes_gcm"`, `"aes_ccm"`, `"chacha20_poly1305"`,
              `"kasumi_f8"`, `"snow3g_uae2"`, `"aes_eea2"`, `"zuc_eea3"`, `"snow_v"`,
              `"snow_v_gcm"`, `"sm4_ecb"`, `"sm4_cbc"`, `"sm4_ctr"`, `"sm4_gcm"`, `"sm4_ccm"`,
              mapping to `odp_cipher_alg_t`
    - default: `odp_crypto_session_param_init()`
  - element: `cipher_key_data`
    - necessity: required if `cipher_alg` != `"null"`
    - type: byte value array
  - element: `cipher_key_len`
    - necessity: required if `cipher_alg` != `"null"`
    - type: integer
  - element: `cipher_iv_len`
    - necessity: optional
    - type: integer
    - default: `odp_crypto_session_param_init()`
  - element: `auth_alg`
    - necessity: optional
    - type: string
    - values: `"null"`, `"md5_hmac"`, `"sha1_hmac"`, `"sha224_hmac"`, `"sha256_hmac"`,
              `"sha384_hmac"`, `"sha512_hmac"`, `"sha3_224_hmac"`, `"sha3_256_hmac"`,
              `"sha3_384_hmac"`, `"sha3_512_hmac"`, `"aes_gmac"`, `"aes_cmac"`, `"aed_xcbc_mac"`,
              `"kasumi_f9"`, `"snow3g_uia2"`, `"aes_eia2"`, `"zuc_eia3"`, `"snow_v_gmac"`,
              `"sm3_hmac"`, `"sm4_gmac"`, `"md5"`, `"sha1"`, `"sha224"`, `"sha3_256"`,
              `"sha3_384"`, `"sha3_512"`, `"sm3"`, mapping to `odp_auth_alg_t`
  - element: `auth_key_data`
    - necessity: required if `auth_alg` != `"null"`
    - type: byte value array
  - element: `auth_key_len`
    - necessity: required if `auth_alg` != `"null"`
    - type: integer
  - element: `auth_iv_len`
    - necessity: optional
    - type: integer
    - default: `odp_crypto_session_param_init()`
  - element: `auth_digest_len`
    - necessity: optional
    - type: integer
    - values: algorithm and capability dependent
  - element: `auth_aad_len`
    - necessity: optional
    - type: integer
    - default: `odp_crypto_session_param_init()`
  - element: `compl_queue`
    - necessity: required
    - type: string, max `ODP_QUEUE_NAME_LEN`
    - values: queue domain resource name

### DMA

- name in configuration file: `dma`
- type: list of groups
- `dma` entries:
  - element: `name`
    - necessity: required
    - type: string, max `ODP_DMA_NAME_LEN`

### Flows

- name in configuration file: `flows`
- type: list of groups
- `flows` entries:
  - element: `template`
    - necessity: optional
    - type: integer
    - values: number of resources to be instantiated based on the template
  - element: `name`
    - necessity: required
    - type: string, or in case of a template, a list of name prefix string, initial index value
            integer and increment value integer, which will be concatenated to a string
  - element: `input`
    - necessity: required if no `output`
    - type: string, max `ODP_QUEUE_NAME_LEN`, or in case of a template, a list of name prefix
            string, initial index value integer and increment value integer, which will be
            concatenated to a string, max `ODP_QUEUE_NAME_LEN`
    - values: queue domain resource name
  - element: `output`
    - necessity: required if no `input`
    - type: string, max `ODP_QUEUE_NAME_LEN`, or in case of a template, a list of name prefix
            string, initial index value integer and increment value integer, which will be
            concatenated to a string, max `ODP_QUEUE_NAME_LEN`
    - values: queue domain resource name
  - element: `work`
    - necessity: required
    - type: list of groups
- `work` entries:
  - element: `type`
    - necessity: required
    - type: string
    - values: `"work_forward"`, `"work_global_forward"`, `"work_packet_copy"`,
              `"work_packet_source"`, `"work_sink"`, `"work_timeout_source"`, `"work_wait"`
  - element: `param`
    - necessity: optional
    - type: list
    - values: work dependent

### Pktios

- name in configuration file: `pktios`
- type: list of groups
- `pktios` entries:
  - element: `name`
    - necessity: required
    - type: string
  - element: `iface`
    - necessity: required
    - type: string
  - element: `pool`
    - necessity: required
    - type: string
    - values: pool domain resource name
  - element: `inmode`
    - necessity: optional
    - type: string
    - values: `"queue"`, `"schedule"`, `"direct"`, mapping to `odp_pktin_mode_t`, with `"direct"`,
              queues have to be manually queried with the related packet I/O handle
    - default: `"queue"`
  - element: `priority`
    - necessity: optional
    - type: integer
    - default: `odp_schedule_default_prio()`
  - element: `group`
    - necessity: optional
    - type: string
    - values: schedule domain group resource name
    - default: `odp_queue_param_init()`
  - element: `sync`
    - necessity: optional
    - type: string
    - values: `"parallel"`, `"atomic"`, `"ordered"`, mapping to `odp_schedule_sync_t`
    - default: `odp_queue_param_init()`
  - element: `size`
    - necessity: optional
    - type: integer
    - values: size of the queue in non-direct receive modes
  - element: `outmode`
    - necessity: optional
    - type: string
    - values: `"queue"`, `"direct"`, mapping to `odp_pktout_mode_t`, with `"direct"`, queues have
              to be manually queried with the related packet I/O handle
    - default: `"queue"`
  - element: `classifier_enable`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_queue_param_t` boolean
    - default: `odp_pktin_queue_param_init()`
  - element: `parse_layer`
    - necessity: optional
    - type: string
    - values: `"none"`, `"l2"`, `"l3"`, `"l4"`, `"all"`, mapping to `odp_proto_layer_t`
    - default: `odp_pktio_config_init()`
  - element: `hash_enable`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_queue_param_t` boolean
    - default: `odp_pktin_queue_param_init()`
  - element: `hash_ipv4_udp`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_hash_proto_t` bitfield
    - default: `0`
  - element: `hash_ipv4_tcp`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_hash_proto_t` bitfield
    - default: `0`
  - element: `hash_ipv4`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_hash_proto_t` bitfield
    - default: `0`
  - element: `hash_ipv6_udp`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_hash_proto_t` bitfield
    - default: `0`
  - element: `hash_ipv6_tcp`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_hash_proto_t` bitfield
    - default: `0`
  - element: `hash_ipv6`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to `odp_pktin_hash_proto_t` bitfield
    - default: `0`
  - element: `num_in_queues`
    - necessity: optional
    - type: integer
    - default: `odp_pktio_config_init()`
  - element: `num_out_queues`
    - necessity: optional
    - type: integer
    - default: `odp_pktout_queue_param_init()`
  - element: `promisc_enable`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to boolean
    - default: `0`
  - element: `lso_enable`
    - necessity: optional
    - type: integer
    - values: `0`, `1`, mapping to boolean
    - default: `0`
  - element: `mtu`
    - necessity: optional
    - type: integer

### Pools

- name in configuration file: `pools`
- type: list of groups
- `pools` entries:
  - element: `name`
    - necessity: required
    - type: string, max `ODP_POOL_NAME_LEN`
  - element: `type`
    - necessity: required
    - type: string
    - values: `"packet"`, `"buffer"`, `"timeout"`, `"dma_completion"`, mapping to `odp_pool_type_t`
  - element: `size`
    - necessity: required if `type` == `"packet"` or `"buffer"`
    - type: integer
  - element: `cache_size`
    - necessity: optional
    - type: integer
    - default: `odp_pool_param_init()`, `odp_dma_pool_param_init()`
  - element: `num`
    - necessity: required
    - type: integer

### Queues

- name in configuration file: `queues`
- type: list of groups
- `queues` entries:
  - element: `template`
    - necessity: optional
    - type: integer
    - values: number of resources to be instantiated based on the template
  - element: `name`
    - necessity: required
    - type: string, max `ODP_QUEUE_NAME_LEN`, or in case of a template, a list of name prefix
            string, initial index value integer and increment value integer, which will be
            concatenated to a string, max `ODP_QUEUE_NAME_LEN`
  - element: `type`
    - necessity: optional
    - type: string
    - values: `"plain"`, `"schedule"`, mapping to `odp_queue_type_t` or domain name which provides
              queues with `name` as the provided queue
    - default: `odp_queue_param_init()`
  - element: `priority`
    - necessity: optional
    - type: integer
    - default: `odp_schedule_default_prio()`
  - element: `group`
    - necessity: optional
    - type: string
    - values: schedule domain group resource name
    - default: `odp_queue_param_init()`
  - element: `sync`
    - necessity: optional
    - type: string
    - values: `"parallel"`, `"atomic"`, `"ordered"`, mapping to `odp_schedule_sync_t`
    - default: `odp_queue_param_init()`
  - element: `size`
    - necessity: optional
    - type: integer
    - values: size of the queue

### Scheduler

- name in configuration file: `scheduler`
- type: group with nested list `groups` of groups
- `groups` entries:
  - element: `name`
    - necessity: required
    - type: string

### Stash

- name in configuration file: `stash`
- type: list of groups
- `stash` entries:
  - element: `name`
    - necessity: required
    - type: string
  - element: `type`
    - necessity: optional
    - type: string
    - values: `"default"`, `"fifo"`, mapping to `odp_stash_type_t`
    - default: `odp_stash_param_init()`
  - element: `put_mode`
    - necessity: optional
    - type: string
    - values: `"mt"`, `"st"`, `"local"`, mapping to `odp_stash_op_mode_t`
    - default: `odp_stash_param_init()`
  - element: `get_mode`
    - necessity: optional
    - type: string
    - values: `"mt"`, `"st"`, `"local"`, mapping to `odp_stash_op_mode_t`
    - default: `odp_stash_param_init()`
  - element: `num`
    - necessity: required
    - type: integer
  - element: `size`
    - necessity: required
    - type: integer
    - values: size of the objects to be stashed
  - element: `cache_size`
    - necessity: optional
    - type: integer
    - default: `odp_stash_param_init()`

### Timers

- name in configuration file: `timers`
- type: list of groups
- `timers` entries:
  - element: `name`
    - necessity: required
    - type: string, max `ODP_TIMER_POOL_NAME_LEN`
  - element: `clk_src`
    - necessity: optional
    - type: integer
    - values: `"src0"`, `"src1"`, `"src2"`, `"src3"`, `"src4"`, `"src5"`, mapping to
              `odp_timer_clk_src_t`
    - default: `odp_timer_pool_param_init()`
  - element: `res_ns`
    - necessity: optional
    - type: integer
    - default: `odp_timer_pool_param_init()`
  - element: `res_hz`
    - necessity: optional
    - type: integer
    - default: `odp_timer_pool_param_init()`
  - element: `min_tmo`
    - necessity: required
    - type: integer
  - element: `max_tmo`
    - necessity: required
    - type: integer
  - element: `num`
    - necessity: required
    - type: integer

### Workers

- name in configuration file: `workers`
- type: list of groups
- `workers` entries:
  - element: `name`
    - necessity: required
    - type: string
  - element: `type`
    - necessity: required
    - type: string
    - values: `"plain"`, `"schedule"`
  - element: `burst_size`
    - necessity: optional
    - type: integer
    - default: `32`
  - element: `wait_ns`
    - necessity: optional
    - type: integer
    - values: for `"schedule"` workers, the minimum time to wait for an event, `0` for no waiting,
              `-1` for waiting indefinitely. For `"plain"` workers, the wait time between poll
	      rounds.
    - default: for `"schedule"` workers, `1000000000` nanoseconds (`1` second), for `"plain"`
               workers, `0`.
  - element: `inputs`
    - necessity: required if `type` == `"plain"`
    - type: array
    - values: for `"schedule"` workers, array of schedule domain group resource names, for
              `"plain"` workers, array of input queue domain resource names
  - element: `outputs`
    - necessity: optional
    - type: array
    - values: array of output queue resource names

## Work

Work elements are where actual application work is carried out. Each work is part of a work chain
which in turn is part of a flow and flows are then finally attached to a queue. Tester then
either sets up polling or scheduling of events from these queues. Once events are received from a
queue, flows which has the queue set as "input" gets executed. The events that were received can be
consumed by the work steps in a flow. The execution of the flow is stopped once all the events are
consumed and tester moves to poll/schedule additional events. If events remain unconsumed after
a flow has been fully executed, they are simply freed.

Tester also supports event generation or generic code execution through output flows, where a
queue is marked as "output" flow, where again a set of events is passed to flow work steps but
instead of consuming the events, they are produced to the passed event set. Output flows are
executed once per poll/scheduling round and after input flows have been handled.

### Forward

- name in configuration file: `work_forward`
- type: input
- info: forward events to a queue, consumes successfully forwarded events
- parameter list:
  - index 0: queue resource name
    - type: string

### Global forward

- name in configuration file: `work_global_forward`
- type: input
- info: forward events to a set of queues based on worker thread ID, consumes successfully
        forwarded events
- parameter list:
  - index 0..N: queue resource names
    - type: string

### Packet copy

- name in configuration file: `work_packet_copy`
- type: input
- info: copies passed events in case of packet events, using given pool, no events consumed
- parameter list:
  - index 0: pool resource name

### Packet source

- name in configuration file: `work_packet_source`
- type: output
- info: produces events from given pool of given length
- parameter list:
  - index 0: pool resource name
    - type: string
  - index 1: packet length
    - type: integer

### Sink

- name in configuration file: `work_sink`
- type: input
- info: frees all passed events, all events consumed

### Timeout source

- name in configuration file: `work_timeout_source`
- type: output
- info: produces timeouts from given timer with given timeout pool and timeout. Timer is rearmed
        once timeout is handled and freed to the pool
- parameter list:
  - index 0: timer resource name
    - type: string
  - index 1: pool resource name
    - type: string
  - index 2: timeout in nanoseconds
    - type: integer

### Wait

- name in configuration file: `work_wait`
- type: input
- info: waits a given amount, no events consumed
- parameter list:
  - index 0: time to wait in nanoseconds
