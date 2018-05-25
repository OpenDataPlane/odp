/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#ifdef HAS_SYS_RANDOM
#include <sys/random.h>
#else
#include <sys/time.h>
#endif
#include <sys/prctl.h>
#include <signal.h>

#include <fdserver.h>
#include <fdserver_internal.h>
#include <fdserver_common.h>

#define FDSERVER_BACKLOG 5
/* define the tables of file descriptors handled by this server: */
#define FDSERVER_MAX_ENTRIES 256
#define FDSERVER_MAX_CONTEXTS 16
struct fdentry {
	uint64_t key;
	int  fd;
};

struct fdcontext_entry {
	uint32_t index;
	uint32_t token;
	int max_entries;
	int num_entries;
	struct fdentry fd_table[0];
};
static struct fdcontext_entry *context_table[FDSERVER_MAX_CONTEXTS] = {NULL};

static int do_quit = 0;
static void hangup_handler(int signo __attribute__((unused)))
{
	do_quit = 1;
}

static void handle_new_context(int client_sock)
{
	size_t size;
	struct fdserver_context context;
	struct fdcontext_entry *entry;
	uint32_t index;

	for (index = 0; index < FDSERVER_MAX_CONTEXTS; index++) {
		if (context_table[index] == NULL)
			break;
	}
	if (index >= FDSERVER_MAX_CONTEXTS) {
		FD_ODP_DBG("Too many contexts\n");
		goto send_error;
	}

	size = sizeof(struct fdcontext_entry) +
		FDSERVER_MAX_ENTRIES * sizeof(struct fdentry);

	entry = malloc(size);
	if (entry != NULL) {
		memset(entry, 0, size);
		entry->index = index;
		entry->token = (uint32_t)rand();
		entry->max_entries = FDSERVER_MAX_ENTRIES;
		entry->num_entries = 0;
		context.index = index;
		context.token = entry->token;
		context_table[index] = entry;
		fdserver_internal_send_msg(client_sock,
					   FD_RETVAL_SUCCESS,
					   &context, 0, -1);
		FD_ODP_DBG("New context %u created\n", index);
		return;
	}

send_error:
	FD_ODP_DBG("Failed to create new context\n");
	context.index = 0;
	context.token = 0;
	fdserver_internal_send_msg(client_sock,
				   FD_RETVAL_FAILURE,
				   &context, 0, -1);
}

static struct fdcontext_entry *find_context(struct fdserver_context *context)
{
	struct fdcontext_entry *entry;

	FD_ODP_DBG("Find context for %u -> 0x%08x\n",
		   context->index, context->token);

	if (context->index >= FDSERVER_MAX_CONTEXTS)
		return NULL;

	entry = context_table[context->index];

	if (entry == NULL || entry->token != context->token)
		return NULL;

	return entry;
}

static void handle_del_context(int sock, struct fdserver_context *ctx)
{
	struct fdcontext_entry *entry;
	int retval;

	entry = find_context(ctx);
	if (entry == NULL) {
		retval = FD_RETVAL_FAILURE;
		goto do_exit;
	}

	context_table[entry->index] = NULL;

	for (int i = 0; i < entry->num_entries; i++)
		close(entry->fd_table[i].fd);

	free(entry);
	retval = FD_RETVAL_SUCCESS;
do_exit:
	fdserver_internal_send_msg(sock, retval, ctx, 0, -1);
}

static int add_fdentry(struct fdcontext_entry *context,
		       uint64_t key, int fd)
{
	if (context->num_entries >= context->max_entries)
		return -1;

	context->fd_table[context->num_entries].key = key;
	context->fd_table[context->num_entries].fd = fd;
	context->num_entries++;

	return 0;
}

static int find_fdentry_from_key(struct fdcontext_entry *context, uint64_t key)
{
	struct fdentry *fd_table;

	fd_table = &(context->fd_table[0]);
	for (int i = 0; i < context->num_entries; i++) {
		if (fd_table[i].key == key)
			return fd_table[i].fd;
	}

	return -1;
}

static int del_fdentry(struct fdcontext_entry *context, uint64_t key)
{
	struct fdentry *fd_table;

	fd_table = &context->fd_table[0];
	for (int i = 0; i < context->num_entries; i++) {
		if (fd_table[i].key == key) {
			close(fd_table[i].fd);
			fd_table[i] = fd_table[--context->num_entries];
			return 0;
		}
	}

	return -1;
}

/*
 * server function
 * receive a client request and handle it.
 * Always returns 0 unless a stop request is received.
 */
static int handle_request(int client_sock)
{
	int command = -1;
	struct fdserver_context ctx;
	struct fdcontext_entry *context;
	uint64_t key = 0;
	int fd = -1;

	/* get a client request: */
	if (fdserver_internal_recv_msg(client_sock, &command,
				       &ctx, &key, &fd) != 0) {
		ODP_ERR("fdserver: Failed to receive message\n");
		return 0;
	}
	switch (command) {
	case FD_REGISTER_REQ:
		context = find_context(&ctx);
		if ((fd < 0) || (context == NULL)) {
			ODP_ERR("Invalid register fd or context\n");
			fdserver_internal_send_msg(client_sock,
						   FD_RETVAL_FAILURE,
						   &ctx, 0, -1);
			return 0;
		}

		if (add_fdentry(context, key, fd) == 0) {
			FD_ODP_DBG("storing {ctx=%u, key=%" PRIu64 "}->fd=%d\n",
				   ctx.index, key, fd);
		} else {
			ODP_ERR("FD table full\n");
			fdserver_internal_send_msg(client_sock,
						   FD_RETVAL_FAILURE,
						   &ctx, 0, -1);
			return 0;
		}

		fdserver_internal_send_msg(client_sock, FD_RETVAL_SUCCESS,
					   &ctx, 0, -1);
		break;

	case FD_LOOKUP_REQ:
		context = find_context(&ctx);
		if (context == NULL) {
			ODP_ERR("invalid lookup context\n");
			fdserver_internal_send_msg(client_sock,
						   FD_RETVAL_FAILURE,
						   &ctx, 0, -1);
			return 0;
		}

		fd = find_fdentry_from_key(context, key);
		if (fd == -1)
			command = FD_RETVAL_FAILURE;
		else
			command = FD_RETVAL_SUCCESS;

		fdserver_internal_send_msg(client_sock, command,
					   &ctx, key, fd);

		FD_ODP_DBG("lookup {ctx=%u, key=%" PRIu64 "}->fd=%d\n",
			   ctx.index, key, fd);
		break;

	case FD_DEREGISTER_REQ:
		FD_ODP_DBG("Delete {ctx: %u, key: %" PRIu64 "}\n",
			   ctx.index, key);
		command = FD_RETVAL_FAILURE;
		context = find_context(&ctx);
		if (context != NULL) {
			if (del_fdentry(context, key) == 0) {
				FD_ODP_DBG("deleted {ctx=%u, key=%"PRIu64"}\n",
					ctx.index, key);
				command = FD_RETVAL_SUCCESS;
			} else {
				FD_ODP_DBG("Failed to delete deleted {ctx=%u, "
					"key=%" PRIu64 "}\n",
					ctx.index, key);
			}
		}
		fdserver_internal_send_msg(client_sock, command, &ctx, key, -1);
		break;

	case FD_NEW_CONTEXT:
		handle_new_context(client_sock);
		break;

	case FD_DEL_CONTEXT:
		FD_ODP_DBG("Delete context %u\n", ctx.index);
		handle_del_context(client_sock, &ctx);
		break;

	default:
		ODP_ERR("Unexpected request: %d\n", command);
		fdserver_internal_send_msg(client_sock, FD_RETVAL_FAILURE,
					   &ctx, 0, -1);
		break;
	}

	return 0;
}

/*
 * server function
 * loop forever, handling client requests one by one
 */
static void wait_requests(int sock)
{
	int c_socket = -1; /* client connection */
	unsigned int addr_sz;
	struct sockaddr_un remote;

	while (!do_quit) {
		addr_sz = sizeof(remote);
		c_socket = accept(sock, (struct sockaddr *)&remote, &addr_sz);
		if (c_socket == -1) {
			if (errno == EINTR)
				continue;

			ODP_ERR("wait_requests: %s\n", strerror(errno));
			return;
		}

		handle_request(c_socket);
		close(c_socket);
	}

	if (c_socket != -1)
		close(c_socket);
}

static void setup_signal_handler(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = hangup_handler;
	sigaction(SIGHUP, &action, NULL);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
}

static void prepare_seed(void)
{
	unsigned int seed = 1001;

#ifdef HAS_SYS_RANDOM
again:
	ssize_t num_bytes;
	num_bytes = getrandom(&seed, sizeof(seed), 0);
	if (num_bytes == -1) {
		if (errno == EINTR)
			goto again;
	}
#else
	struct timeval timeval;

	if (gettimeofday(&timeval, NULL))
		seed = (unsigned int)(timeval.tv_sec);
#endif

	srand(seed);
}

static int _odp_fdserver_init_global(const char *sockpath)
{
	int sock;
	struct sockaddr_un local;
	int res;

	setup_signal_handler();
	prepare_seed();

	/* create UNIX domain socket: */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		ODP_ERR("_odp_fdserver_init_global: %s\n", strerror(errno));
		return -1;
	}
	/* remove previous named socket if it already exists: */
	unlink(sockpath);

	/* bind to new named socket: */
	local.sun_family = AF_UNIX;
	memcpy(local.sun_path, sockpath, sizeof(local.sun_path));
	local.sun_path[sizeof(local.sun_path) - 1] = '\0';
	res = bind(sock, (struct sockaddr *)&local, sizeof(struct sockaddr_un));
	if (res == -1) {
		ODP_ERR("_odp_fdserver_init_global: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	/* listen for incoming conections: */
	if (listen(sock, FDSERVER_BACKLOG) == -1) {
		ODP_ERR("_odp_fdserver_init_global: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	/* wait for clients requests */
	wait_requests(sock); /* Returns when server is stopped  */
	close(sock);
	unlink(sockpath);

	return 0;
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"hangup", no_argument, NULL, 'H'},
		{"path", required_argument, NULL, 'p'},
		{0, 0, 0, 0}
	};
	int opt;
	int option_index = 0;
	const char *path = FDSERVER_SOCKET_PATH;
	struct sockaddr_un local;

	while ((opt = getopt_long(argc, argv,
				  ":Hp:", long_options, &option_index)) != -1) {
		switch (opt) {
		case 'H':
			/* if parent dies, send SIGHUP to this process */
			prctl(PR_SET_PDEATHSIG, SIGHUP);
			break;
		case 'p':
			if (strlen(optarg) >= sizeof(local.sun_path)) {
				ODP_ERR("Path given is too long\n");
				exit(EXIT_FAILURE);
			}
			strcpy(local.sun_path, optarg);
			/* FIXME: check path exists or create it */
			path = local.sun_path;
			break;
		case ':':
			ODP_ERR("Missing argument for %s\n",
				argv[optind - 1]);
			exit(EXIT_FAILURE);
			break;
		case '?':
			/* fall-through */
		default:
			ODP_ERR("Unknown option %c\n", (char)opt);
			break;
		}
	}

	if (_odp_fdserver_init_global(path) != 0)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
