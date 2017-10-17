/* Test file to test basic compression/decompression a
 * ability
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /* _GNU_SOURCE */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>
#include <odp_api.h>
#include <odp/helper/linux.h>

#define DUMP_EACH_PKT

#define app_dbg printf

#define app_err(fmt, ...) \
	fprintf(stderr, "%s:%d:%s(): Error: " fmt, __FILE__, \
		__LINE__, __func__, ##__VA_ARGS__)

/** @def SHM_PKT_POOL_SIZE
 * @brief Size of the shared memory block
 */
#define SHM_PKT_POOL_SIZE      (512 * 2048 * 2)

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE  (1024 * 64)

#define SHA_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32

unsigned char sha1_digest[SHA_DIGEST_LENGTH] = {
	0x11, 0xf1, 0x9a, 0x3a, 0xec, 0x1a, 0x1e, 0x8e, 0x65, 0xd4, 0x9a,
	0x38, 0x0c, 0x8b, 0x1e, 0x2c, 0xe8, 0xb3, 0xc5, 0x18};

unsigned char sha256_digest[SHA256_DIGEST_LENGTH] = {
	0xf5, 0x53, 0xcd, 0xb8, 0xcf, 0x1, 0xee, 0x17, 0x9b, 0x93, 0xc9,
	0x68, 0xc0, 0xea, 0x40, 0x91, 0x6, 0xec, 0x8e, 0x11, 0x96, 0xc8,
	0x5d, 0x1c, 0xaf, 0x64, 0x22, 0xe6, 0x50, 0x4f, 0x47, 0x57};

unsigned char str[] = "etaonrishd";

/**
 * Parsed command line arguments. Describes test configuration.
 */
typedef struct {
	/**
	* Maximum number of outstanding encryption requests. Note code
	* poll for results over queue and if nothing is available it can
	* submit more encryption requests up to maximum number specified by
	* this option. Specified through -f or --flight option.
	*/
	int in_flight;

	/**
	* Number of iteration to repeat operation to get good
	* average number. Specified through -i or --terations option.
	* Default is 1.
	*/
	int iteration_count;

	/**
	* Payload size to test. If 0 set of predefined payload sizes
	* is tested. Specified through -p or --payload option.
	*/
	uint32_t payload_length;

	/**
	* Pointer to selected algorithm to test. If NULL all available
	* alogorthims are tested. Name of algorithm is passed through
	* -a or --algorithm option.
	*/
	char *alg;

	/**
	* Input file
	* */
	char *infile;

	/**
	* Output file
	* */
	char *outfile;

	/**
	* Operation type:
	* "comp" - compression
	* "decomp" - decompression
	* "auth" - auth
	* "comp+auth" - compression and authentication
	* */

	const char *op;

	int async;

	FILE *in;
	FILE *out;
	uint32_t pkt_len;
	odp_queue_t compl_queue;
	int compress;
} comp_args_t;

static void parse_args(int argc, char *argv[], comp_args_t *cargs);
static void usage(char *progname);
static int process(comp_args_t *, odp_comp_op_param_t *);

static void print_cargs(comp_args_t *pcargs)
{
	printf("==== PRINT ARGS\n");
	printf("infile: %s\n", pcargs->infile);
	printf("outfile: %s\n", pcargs->outfile);
	printf("Algorithm: %s\n", pcargs->alg);
	printf("Compress: %d\n", pcargs->compress);
	printf("iteration : %d\n", pcargs->iteration_count);
	printf("async mode : %d\n", pcargs->async);
}

static int consume_data(odp_comp_op_result_t *result, FILE *out)
{
	uint32_t len = 0;
	uint32_t offset;
	uint8_t *data;
	uint32_t end;
	odp_packet_t out_pkt = result->output.pkt.packet;

	offset = result->output.pkt.data_range.offset;
	end = offset + result->output.pkt.data_range.length;

	app_dbg("%s:%d odp_packet_len %d "
		"odp_packet_seg_len %d length %u\n",
		__func__, __LINE__,
		odp_packet_len(out_pkt),
		odp_packet_seg_len(out_pkt),
		(unsigned int)result->output.pkt.data_range.length);

	/* read processed data in to file */
	while (offset < end) {
		data = odp_packet_offset(out_pkt, offset, &len, NULL);
		/* len gives segment length at ptr 'data' and is not actual
		   data available
		   in buffer. So check and adjust that we dont exceed limit here
		*/
		if (offset + len > end)
			len = end - offset;
		app_dbg("%s:%d offset %d cur_seg_len %u, end %u\n",
			__func__, __LINE__,
			offset,
			len,
			end);

		fwrite(data, 1, len, out);
		offset += len;
	}
	return 0;
}

static int ODP_UNUSED dump_total(uint32_t end, odp_packet_t pkt, FILE *out)
{
	size_t offset;
	uint8_t *data;

	odp_packet_t out_pkt = pkt;
	uint32_t    len = 0;

	offset = 0;

	app_dbg("odp_packet_len %d odp_packet_seg_len %d length %u\n",
		odp_packet_len(out_pkt),
		odp_packet_seg_len(out_pkt), (unsigned int)end);

	/* read processed data in to file */
	if (offset < end) {
		data = odp_packet_offset(out_pkt, offset, &len, NULL);

		app_dbg("reading from offset %u\n", (unsigned int)offset);

		/* len gives segment length at ptr 'data' and is not
		actual data available in buffer. So check and adjust that
		we dont exceed limit here
		*/
		if (offset + len > end)
			len = end - offset;

		fwrite(data, 1, len, out);

		offset += len;
	}
	return 0;
}

static int process(comp_args_t *pcargs, odp_comp_op_param_t *op_params)
{
	int ret;
	odp_event_t ev;
	odp_comp_op_result_t result;
	uint32_t total_len = 0;
	odp_packet_t out_pkt;
	odp_packet_data_range_t *out_pkt_range;

	do {
		app_dbg("out packet offset %d length %d\n",
			op_params->output.pkt.data_range.offset,
			op_params->output.pkt.data_range.length);

		if (pcargs->async) {
			ret = (pcargs->compress) ?
				odp_comp_compress_enq(op_params) :
				odp_comp_decomp_enq(op_params);
			ev = odp_queue_deq(pcargs->compl_queue);
			odp_packet_t compl_ev =
			odp_comp_packet_from_event(ev);
			odp_comp_result(compl_ev,
					&result);
		} else {
			ret = (pcargs->compress) ?
				odp_comp_compress(op_params, &result) :
				odp_comp_decomp(op_params, &result);
		}

		if (ret && (result.err != ODP_COMP_ERR_NONE &&
			    result.err !=
			    ODP_COMP_ERR_OUT_OF_SPACE)) {
			app_err("Operation Failed.ret %d,"
				"result.err %d\n",
				ret, result.err);
			ret = -1;
			break;
		}

		out_pkt = result.output.pkt.packet;
		out_pkt_range = &result.output.pkt.data_range;

		total_len += out_pkt_range->length;

		/* dump out of each operation
		   we can optimise test case more by deferring
		   file
		   writes at end of this inner-loop Or when
		   pool gets out of memory. However this test
		   is not so performance but function
		   orientated,
		   so we will it here as is for now.
		*/
		consume_data(&result, pcargs->out);

		/* adjust available length by number of bytes consumed */
		op_params->output.pkt.data_range.length -=
			out_pkt_range->length;

		/* Though data is already consumed so output
		   packet
		   is free to use from offset 0, but for
		   illustration
		   sake we are keeping extend_packet call and
		   changing offset
		   */
		if (result.err == ODP_COMP_ERR_OUT_OF_SPACE) {
			/* extend output packet as returned
			by last
			operation call */
			ret =
			odp_packet_extend_tail(&out_pkt,
					       pcargs->payload_length,
					       NULL,
					       NULL);

			/* set length of data to process by amount
			of exceeded bytes
			*/
			op_params->output.pkt.data_range.length =
						pcargs->payload_length;

			if (ret < 0) {
				app_err("odp_packet_extend_tail\n");
				/* in any case, we have
				   consumed all of the data
				   written so far, reset
				   offset and len
				   */
				op_params->output.pkt.data_range.offset = 0;
				out_pkt_range->length = 0;
				op_params->output.pkt.data_range.length =
							odp_packet_len(out_pkt);
			}
			app_dbg("Extended packet. len %d\n",
				odp_packet_len(out_pkt));
		}

		/* increment offset by length of bytes written
		   as result of last operation
		   */
		op_params->output.pkt.data_range.offset +=
			out_pkt_range->length;
		op_params->output.pkt.packet = out_pkt;
	} while (result.err == ODP_COMP_ERR_OUT_OF_SPACE);
	return ret;
}

static int init(comp_args_t *pcargs, odp_comp_op_param_t *op_param)
{
	int                       ret = 0;
	odp_comp_session_t         session = ODP_COMP_SESSION_INVALID;
	odp_comp_session_param_t   params;
	odp_comp_ses_create_err_t  status;
	FILE *in = NULL;
	FILE *out = NULL;

	print_cargs(pcargs);

	in = fopen(pcargs->infile, "rb");
	if (in == NULL) {
		app_err("Unable to open input file %s\n",
			pcargs->infile);
		return -1;
	}

	out = fopen(pcargs->outfile, "wb");
	if (out == NULL) {
		app_err("Unable to open output file %s\n",
			pcargs->outfile);
		fclose(in);
		return -1;
	}

	memset(&params, 0, sizeof(odp_comp_session_param_t));

	if (strstr(pcargs->alg, "zlib") != NULL) {
		params.comp_algo = ODP_COMP_ALG_ZLIB;
	} else if (strstr(pcargs->alg, "deflate") != NULL) {
		params.comp_algo = ODP_COMP_ALG_DEFLATE;
	} else {
		app_err("%s not supported.\n", pcargs->alg);
		return -1;
	}

	if (strstr(pcargs->alg, "sha1") != NULL)
		params.hash_algo = ODP_COMP_HASH_ALG_SHA1;
	else if (strstr(pcargs->alg, "sha256") != NULL)
		params.hash_algo = ODP_COMP_HASH_ALG_SHA256;

	params.op = ODP_COMP_OP_COMPRESS;
	if (!pcargs->compress)
		params.op = ODP_COMP_OP_DECOMPRESS;

	params.compl_queue = ODP_QUEUE_INVALID;
	params.mode = ODP_COMP_SYNC;
	if (pcargs->async) {
		odp_queue_param_t qparam;

		odp_queue_param_init(&qparam);
		qparam.type = ODP_QUEUE_TYPE_PLAIN;
		params.compl_queue = odp_queue_create("compl_q", &qparam);
		if (params.compl_queue != ODP_QUEUE_INVALID) {
			app_dbg("Set Async Mode of operation.\n");
			params.mode = ODP_COMP_ASYNC;
		} else {
			app_dbg("odp_queue_create failed\n");
			params.compl_queue = ODP_QUEUE_INVALID;
		}
	}
	ret = odp_comp_session_create(&params, &session, &status);
	if (ret && status != ODP_COMP_SES_CREATE_ERR_NONE) {
		app_err("Session creation failed\n");
		fclose(in);
		fclose(out);
		return -1;
	}
	op_param->session = session;
	pcargs->in = in;
	pcargs->out = out;
	pcargs->compl_queue = params.compl_queue;
	return 0;
}

static int term(comp_args_t *pcargs, odp_comp_op_param_t *param)
{
	odp_comp_session_destroy(param->session);
	fclose(pcargs->in);
	fclose(pcargs->out);
	return 0;
}

static void test_comp(comp_args_t *pcargs)
{
	int                       ret;
	uint32_t                  payload_len = 0;
	uint32_t                  len = 0;
	odp_pool_t                pkt_pool;
	odp_packet_t              pkt = ODP_PACKET_INVALID;
	uint8_t                  *data = NULL;
	odp_comp_op_param_t        op_params;
	uint32_t                   flen = 0;
	uint32_t                   read = 0;
	int                         err = 0;
	int32_t                     iteration;
	odp_comp_data_t *in = &op_params.input;
	odp_comp_data_t *out = &op_params.output;

	app_dbg("Enter.........\n");

	pkt_pool = odp_pool_lookup("packet_pool");
	if (ODP_POOL_INVALID == pkt_pool) {
		app_err("Unable to open input file %s\n", pcargs->outfile);
		return;
	}

	ret = init(pcargs, &op_params);
	if (ret < 0)
		return;

	payload_len = (pcargs->payload_length);

	fseek(pcargs->in, 0, SEEK_END);
	flen = ftell(pcargs->in);

	/* as used by fwrite, reset to 0 */
	pkt = odp_packet_alloc(pkt_pool, payload_len);
	if (ODP_PACKET_INVALID == pkt) {
		app_err("Failed to allocate packet\n");
		term(pcargs, &op_params);
		return;
	}

	app_dbg("Allocated input packet of len %d\n", odp_packet_len(pkt));
	in->pkt.packet = pkt;

	/* Allocate output packet */
	pkt = odp_packet_alloc(pkt_pool, payload_len);
	if (ODP_PACKET_INVALID == pkt) {
		app_err("Failed to allocate packet\n");
		term(pcargs, &op_params);
		return;
	}
	out->pkt.packet = pkt;

	app_dbg("Allocated input packet of len %d\n", odp_packet_len(pkt));

	app_dbg("flen %d\n", flen);
	app_dbg("input pkt 0x%lx\n", (unsigned long)in->pkt.packet);

	iteration = 0;

	while (!err && iteration++ < pcargs->iteration_count) {
		fseek(pcargs->in, 0, SEEK_SET);
		read = 0;

		odp_packet_seg_t seg = odp_packet_first_seg(in->pkt.packet);

		out->pkt.data_range.offset  = 0;
		out->pkt.data_range.length = odp_packet_len(
					out->pkt.packet);
		printf("Loop %d\n", iteration);
		while (!err && read < flen) {
			if (seg == ODP_PACKET_SEG_INVALID) {
				app_dbg("consumed last segment!"
					"Reset to first\n");
				seg = odp_packet_first_seg(in->pkt.packet);
			}

			data = odp_packet_seg_data(in->pkt.packet, seg);
			len = odp_packet_seg_data_len(in->pkt.packet, seg);
			/* read from file in to segment data pointer
			   up to seg data length bytes
			   */
			len = fread(data, 1, len, pcargs->in);
			/* printf("app data @ 0x%lx %s len %d\n",
					(unsigned long)data, data,len); */

			/* updated bytes read from file*/
			read += len;

			/* if whole bytes have been consumed,
			   mark current as last packet
			   */
			if (read >= flen)
				op_params.last   = 1;
			else
				op_params.last   = 0;

			app_dbg("~~~~~~~~~~~~~~~~~~Feed Next Chunk\n");
			in->pkt.data_range.offset  = 0;
			in->pkt.data_range.length = len;
			/* process current segment */
			ret = process(pcargs, &op_params);
			if (ret < 0)
				err = 1;

			/* get next segment to process */
			seg = odp_packet_next_seg(in->pkt.packet, seg);
		}
	}

	/* free up pkt used by operation */
	odp_packet_free(out->pkt.packet);
	odp_packet_free(in->pkt.packet);

	term(pcargs, &op_params);
}

int main(int argc, char *argv[])
{
	comp_args_t cargs;
	odp_pool_t pool;
	odp_pool_param_t params;
	odp_instance_t instance;
	odp_pool_capability_t capa;
	uint32_t max_seg_len;

	memset(&cargs, 0, sizeof(cargs));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &cargs);

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		app_err("ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	odp_init_local(instance, ODP_THREAD_WORKER);

	/* Create packet pool */
	odp_pool_param_init(&params);

	if (odp_pool_capability(&capa)) {
		app_err("Pool capability request failed.\n");
		exit(EXIT_FAILURE);
	}

	max_seg_len = capa.pkt.max_seg_len;

	/** @def POOL_NUM_PKT
	 * Number of packets in the pool
	 */
#define POOL_NUM_PKT  64

	printf("max_seg_len %d\n", max_seg_len);

	params.pkt.seg_len = max_seg_len;
	params.pkt.len	   = max_seg_len;
	params.pkt.num	   = POOL_NUM_PKT;
	params.type	   = ODP_POOL_PACKET;
	pool = odp_pool_create("packet_pool", &params);

	if (pool == ODP_POOL_INVALID) {
		app_err("packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_pool_print(pool);

	if (cargs.infile == NULL ||
	    cargs.outfile == NULL) {
		usage(argv[0]);
		exit(1);
	}

	if (!cargs.payload_length ||
	    cargs.payload_length > max_seg_len) {
		/* max_seg_len is maximum allowed physical contiguous
		   area.ensure payload length don't exceed
		   maximum segment length */
		app_dbg("Re-setting payload length %d to maximum allowed %d\n",
			cargs.payload_length,
			max_seg_len);
		cargs.payload_length = max_seg_len;
	}

	test_comp(&cargs);

	odp_pool_destroy(pool);
	odp_term_local();
	odp_term_global(instance);

	return 0;
}

static void parse_args(int argc, char *argv[], comp_args_t *cargs)
{
	int opt;
	int long_index;
	static const struct option longopts[] = {
		{"flight", optional_argument, NULL, 'f'},
		{"help", no_argument, NULL, 'h'},
		{"payload", optional_argument, NULL, 'p'},
		{"algorithm", required_argument, NULL, 'a'},
		{"input", required_argument, NULL, 's'},
		{"output", required_argument, NULL, 'd'},
		{"compress", required_argument, NULL, 'c'},
		{"sync", required_argument, NULL, 'b'},
		{"loop", optional_argument, NULL, 'l'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+a:f:hs:p:d:c:s:l:b:";

	if (argc <= 1) {
		usage(argv[0]);
		exit(-1);
	}

	/* let helper collect its own arguments (e.g. --odph_proc) */
	odph_parse_options(argc, argv, shortopts, longopts);

	cargs->in_flight = 1;
	cargs->iteration_count = 1;
	cargs->payload_length = 0;
	cargs->alg = NULL;
	cargs->infile = NULL;
	cargs->outfile = NULL;
	cargs->compress = 1;

	opterr = 0; /* do not issue errors on helper options */

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;  /* No more options */

		switch (opt) {
		case 'a':
			cargs->alg = optarg;
			app_dbg("algo name %s\n", cargs->alg);
			if (cargs->alg == NULL) {
				app_err("cannot test compression '%s'"
				"configuration\n", optarg);
				usage(argv[0]);
				exit(-1);
			}
		break;
		case 'f':
			cargs->in_flight = atoi(optarg);
		break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		break;
		case 's':
			cargs->infile = optarg;
			printf("Input filename %s\n", cargs->infile);
		break;
		case 'd':
			cargs->outfile = optarg;
			printf("Output filename %s\n", cargs->outfile);
		break;
		case 'c':
			cargs->compress = atoi(optarg);
			printf("Operation Type %s\n", cargs->compress ?
						      "comp" : "decomp");
		break;
		case 'p':
			cargs->payload_length = atoi(optarg);
		break;
		case 'b':
			cargs->async = atoi(optarg) ? 0 : 1;
			printf("async %d\n", cargs->async);
		break;
		case 'l':
			cargs->iteration_count = atoi(optarg);
		break;

		default:
		break;
		}
	}
	optind = 1; /* reset 'extern optind' from the getopt lib */
	if (cargs->alg == NULL) {
		usage(argv[0]);
		exit(-1);
	}
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n Usage: %s OPTIONS\n", progname);
	printf("\n To run compression tests\n"
	"  E.g. %s -s <src_file> -d <dest_file> -a deflate -c 1 -b 0 -l 10\n"
	"\n", progname);

	printf("\n"
	"  -s, --src file          source file name\n"
	"  -d, --destination file  destination file name\n"
	"  -c, --compress <1/0)    1 to compress,0 to decompress\n"
	"  -a, --algo	           deflate,zlib,def_sha1,def_sha256\n"
	"  -p, --payload           payload length for zlib,deflate.\n"
	"  -b, --blocking call     if 0, operation would be invoked in async"
	" mode.\n"
	"  -l, --loop count        test case run count..\n"
	"  -h, --help              Display help and exit.\n"
	"\n");
}
