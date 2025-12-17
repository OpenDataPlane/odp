/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 */

/*
 * This file implements a file descriptor sharing server enabling
 * sharing of file descriptors between processes, regardless of fork time.
 *
 * File descriptors are process scoped, but they can be "sent and converted
 * on the fly" between processes using special unix domain socket ancillary
 * data.
 * The receiving process gets a file descriptor "pointing" to the same thing
 * as the one sent (but the value of the file descriptor itself may be different
 * from the one sent).
 * Because ODP applications are responsible for creating ODP threads (i.e.
 * pthreads or linux processes), ODP has no control on the order things happen:
 * Nothing prevent a thread A to fork B and C, and then C creating a pktio
 * which will be used by A and B to send/receive packets.
 * Assuming this pktio uses a file descriptor, the latter will need to be
 * shared between the processes, despite the "non convenient" fork time.
 * The shared memory allocator is likely to use this as well to be able to
 * share memory regardless of fork() time.
 * This server handles a table of {(context,key)<-> fd} pair, and is
 * interfaced by the following functions:
 *
 * _odp_fdserver_register_fd(context, key, fd_to_send);
 * _odp_fdserver_deregister_fd(context, key);
 * _odp_fdserver_lookup_fd(context, key);
 *
 * which are used to register/deregister or query for file descriptor based
 * on a context and key value couple, which has to be unique.
 *
 * Note again that the file descriptors stored here are local to this server
 * process and get converted both when registered or looked up.
 */

#include <odp_posix_extensions.h>
#include <odp_config_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_debug_internal.h>
#include <odp_fdserver_internal.h>
#include <odp_string_internal.h>

#include <sys/prctl.h>
#include <signal.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define FDSERVER_SOCKPATH_MAXLEN 255
#define FDSERVER_SOCK_FORMAT "%s/%s/odp-%d-fdserver"
#define FDSERVER_SOCKDIR_FORMAT "%s/%s"
#define FDSERVER_DEFAULT_DIR "/dev/shm"
#define FDSERVER_BACKLOG 5

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* Debug level for the FD server */
#define FD_DBG  3

/* define the tables of file descriptors handled by this server: */
#define FDSERVER_MAX_ENTRIES (CONFIG_SHM_BLOCKS + CONFIG_INTERNAL_SHM_BLOCKS)
typedef struct fdentry_s {
	fd_server_context_e context;
	uint64_t key;
	int  fd;
} fdentry_t;
static fdentry_t *fd_table;
static int fd_table_nb_entries;

/*
 * define the message struct used for communication between client and server
 * (this single message is used in both direction)
 * The file descriptors are sent out of band as ancillary data for conversion.
 */
typedef struct fd_server_msg {
	int command;
	fd_server_context_e context;
	uint64_t key;
} fdserver_msg_t;
/* possible commands are: */
#define FD_REGISTER_REQ		1  /* client -> server */
#define FD_REGISTER_ACK		2  /* server -> client */
#define FD_REGISTER_NACK	3  /* server -> client */
#define FD_LOOKUP_REQ		4  /* client -> server */
#define FD_LOOKUP_ACK		5  /* server -> client */
#define FD_LOOKUP_NACK		6  /* server -> client */
#define FD_DEREGISTER_REQ	7  /* client -> server */
#define FD_DEREGISTER_ACK	8  /* server -> client */
#define FD_DEREGISTER_NACK	9  /* server -> client */
#define FD_SERVERSTOP_REQ	10 /* client -> server (stops) */

/*
 * Client and server function:
 * Send a fdserver_msg, possibly including a file descriptor, on the socket
 * This function is used both by:
 * -the client (sending a FD_REGISTER_REQ with a file descriptor to be shared,
 *  or FD_LOOKUP_REQ/FD_DEREGISTER_REQ without a file descriptor)
 * -the server (sending FD_REGISTER_ACK/NACK, FD_LOOKUP_NACK,
 *  FD_DEREGISTER_ACK/NACK... without a fd or a
 *  FD_LOOKUP_ACK with a fd)
 * This function make use of the ancillary data (control data) to pass and
 * convert file descriptors over UNIX sockets
 * Return -1 on error, 0 on success.
 */
static int send_fdserver_msg(int sock, int command,
			     fd_server_context_e context, uint64_t key,
			     int fd_to_send)
{
	struct msghdr socket_message;
	struct iovec io_vector[1]; /* one msg frgmt only */
	struct cmsghdr *control_message = NULL;
	int *fd_location;
	fdserver_msg_t msg;
	int res;

	char ancillary_data[CMSG_SPACE(sizeof(int))];

	/* prepare the register request body (single fragment): */
	msg.command = command;
	msg.context = context;
	msg.key = key;
	io_vector[0].iov_base = &msg;
	io_vector[0].iov_len = sizeof(fdserver_msg_t);

	/* initialize socket message */
	memset(&socket_message, 0, sizeof(struct msghdr));
	socket_message.msg_iov = io_vector;
	socket_message.msg_iovlen = 1;

	if (fd_to_send >= 0) {
		/* provide space for the ancillary data */
		memset(ancillary_data, 0, CMSG_SPACE(sizeof(int)));
		socket_message.msg_control = ancillary_data;
		socket_message.msg_controllen = CMSG_SPACE(sizeof(int));

		/* initialize a single ancillary data element for fd passing */
		control_message = CMSG_FIRSTHDR(&socket_message);
		control_message->cmsg_level = SOL_SOCKET;
		control_message->cmsg_type = SCM_RIGHTS;
		control_message->cmsg_len = CMSG_LEN(sizeof(int));
		fd_location = (int *)(void *)CMSG_DATA(control_message);
		*fd_location = fd_to_send;
	}
	res = sendmsg(sock, &socket_message, 0);
	if (res < 0) {
		_ODP_ERR("sendmsg() failed: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * Client and server function
 * Receive a fdserver_msg, possibly including a file descriptor, on the
 * given socket.
 * This function is used both by:
 * -the server (receiving a FD_REGISTER_REQ with a file descriptor to be shared,
 *  or FD_LOOKUP_REQ, FD_DEREGISTER_REQ without a file descriptor)
 * -the client (receiving FD_REGISTER_ACK...without a fd or a FD_LOOKUP_ACK with
 * a fd)
 * This function make use of the ancillary data (control data) to pass and
 * convert file descriptors over UNIX sockets.
 * Return -1 on error, 0 on success.
 */
static int recv_fdserver_msg(int sock, int *command,
			     fd_server_context_e *context, uint64_t *key,
			     int *recvd_fd)
{
	struct msghdr socket_message;
	struct iovec io_vector[1]; /* one msg frgmt only */
	struct cmsghdr *control_message = NULL;
	int *fd_location;
	fdserver_msg_t msg;
	char ancillary_data[CMSG_SPACE(sizeof(int))];

	memset(&socket_message, 0, sizeof(struct msghdr));
	memset(ancillary_data, 0, CMSG_SPACE(sizeof(int)));

	/* setup a place to fill in message contents */
	io_vector[0].iov_base = &msg;
	io_vector[0].iov_len = sizeof(fdserver_msg_t);
	socket_message.msg_iov = io_vector;
	socket_message.msg_iovlen = 1;

	/* provide space for the ancillary data */
	socket_message.msg_control = ancillary_data;
	socket_message.msg_controllen = CMSG_SPACE(sizeof(int));

	/* receive the message */
	if (recvmsg(sock, &socket_message, MSG_CMSG_CLOEXEC) < 0) {
		_ODP_ERR("recvmsg() failed: %s\n", strerror(errno));
		return -1;
	}

	*command = msg.command;
	*context = msg.context;
	*key = msg.key;

	/* grab the converted file descriptor (if any) */
	*recvd_fd = -1;

	if ((socket_message.msg_flags & MSG_CTRUNC) == MSG_CTRUNC)
		return 0;

	/* iterate ancillary elements to find the file descriptor: */
	for (control_message = CMSG_FIRSTHDR(&socket_message);
	     control_message != NULL;
	     control_message = CMSG_NXTHDR(&socket_message, control_message)) {
		if ((control_message->cmsg_level == SOL_SOCKET) &&
		    (control_message->cmsg_type == SCM_RIGHTS)) {
			fd_location = (int *)(void *)CMSG_DATA(control_message);
			*recvd_fd = *fd_location;
			break;
		}
	}

	return 0;
}

/* opens and returns a connected socket to the server */
static int get_socket(void)
{
	char sockpath[FDSERVER_SOCKPATH_MAXLEN];
	int s_sock; /* server socket */
	struct sockaddr_un remote;
	int len;

	/* construct the named socket path: */
	len = snprintf(sockpath, FDSERVER_SOCKPATH_MAXLEN, FDSERVER_SOCK_FORMAT,
		       odp_global_ro.shm_dir, odp_global_ro.uid,
		       odp_global_ro.main_pid);

	if (len >= FDSERVER_SOCKPATH_MAXLEN || len >= (int)sizeof(remote.sun_path)) {
		_ODP_ERR("path too long\n");
		return -1;
	}

	s_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s_sock == -1) {
		_ODP_ERR("cannot connect to server: %s\n", strerror(errno));
		return -1;
	}

	remote.sun_family = AF_UNIX;
	_odp_strcpy(remote.sun_path, sockpath, sizeof(remote.sun_path));
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	while (connect(s_sock, (struct sockaddr *)&remote, len) == -1) {
		if (errno == EINTR)
			continue;
		_ODP_ERR("cannot connect to server: %s\n", strerror(errno));
		close(s_sock);
		return -1;
	}

	return s_sock;
}

/*
 * Client function:
 * Register a file descriptor to the server. Return -1 on error.
 */
int _odp_fdserver_register_fd(fd_server_context_e context, uint64_t key,
			      int fd_to_send)
{
	int s_sock; /* server socket */
	int res;
	int command;
	int fd;

	ODP_DBG_LVL(FD_DBG, "FD client register: pid=%d key=%" PRIu64 ", fd=%d\n",
		    getpid(), key, fd_to_send);

	s_sock = get_socket();
	if (s_sock < 0)
		return -1;

	res =  send_fdserver_msg(s_sock, FD_REGISTER_REQ, context, key,
				 fd_to_send);
	if (res < 0) {
		_ODP_ERR("fd registration failure\n");
		close(s_sock);
		return -1;
	}

	res = recv_fdserver_msg(s_sock, &command, &context, &key, &fd);

	if ((res < 0) || (command != FD_REGISTER_ACK)) {
		_ODP_ERR("fd registration failure\n");
		close(s_sock);
		return -1;
	}

	close(s_sock);

	return 0;
}

/*
 * Client function:
 * Deregister a file descriptor from the server. Return -1 on error.
 */
int _odp_fdserver_deregister_fd(fd_server_context_e context, uint64_t key)
{
	int s_sock; /* server socket */
	int res;
	int command;
	int fd;

	ODP_DBG_LVL(FD_DBG, "FD client deregister: pid=%d key=%" PRIu64 "\n",
		    getpid(), key);

	s_sock = get_socket();
	if (s_sock < 0)
		return -1;

	res =  send_fdserver_msg(s_sock, FD_DEREGISTER_REQ, context, key, -1);
	if (res < 0) {
		_ODP_ERR("fd de-registration failure\n");
		close(s_sock);
		return -1;
	}

	res = recv_fdserver_msg(s_sock, &command, &context, &key, &fd);

	if ((res < 0) || (command != FD_DEREGISTER_ACK)) {
		_ODP_ERR("fd de-registration failure\n");
		close(s_sock);
		return -1;
	}

	close(s_sock);

	return 0;
}

/*
 * client function:
 * lookup a file descriptor from the server. return -1 on error,
 * or the file descriptor on success (>=0).
 */
int _odp_fdserver_lookup_fd(fd_server_context_e context, uint64_t key)
{
	int s_sock; /* server socket */
	int res;
	int command;
	int fd;

	s_sock = get_socket();
	if (s_sock < 0)
		return -1;

	res =  send_fdserver_msg(s_sock, FD_LOOKUP_REQ, context, key, -1);
	if (res < 0) {
		_ODP_ERR("fd lookup failure\n");
		close(s_sock);
		return -1;
	}

	res = recv_fdserver_msg(s_sock, &command, &context, &key, &fd);

	if ((res < 0) || (command != FD_LOOKUP_ACK)) {
		_ODP_ERR("fd lookup failure\n");
		close(s_sock);
		return -1;
	}

	close(s_sock);
	_ODP_DBG("FD client lookup: pid=%d, key=%" PRIu64 ", fd=%d\n",
		 getpid(), key, fd);

	return fd;
}

/*
 * request server termination:
 */
static int stop_server(void)
{
	int s_sock; /* server socket */
	int res;

	ODP_DBG_LVL(FD_DBG, "FD sending server stop request\n");

	s_sock = get_socket();
	if (s_sock < 0)
		return -1;

	res =  send_fdserver_msg(s_sock, FD_SERVERSTOP_REQ, 0, 0, -1);
	if (res < 0) {
		_ODP_ERR("fd stop request failure\n");
		close(s_sock);
		return -1;
	}

	close(s_sock);

	return 0;
}

/*
 * server function
 * receive a client request and handle it.
 * Always returns 0 unless a stop request is received.
 */
static int handle_request(int client_sock)
{
	int command;
	fd_server_context_e context;
	uint64_t key;
	int fd;
	int i;

	/* get a client request: */
	recv_fdserver_msg(client_sock, &command, &context, &key, &fd);
	switch (command) {
	case FD_REGISTER_REQ:
		if ((fd < 0) || (context >= FD_SRV_CTX_END)) {
			_ODP_ERR("Invalid register fd or context\n");
			send_fdserver_msg(client_sock, FD_REGISTER_NACK,
					  FD_SRV_CTX_NA, 0, -1);
			return 0;
		}

		/* store the file descriptor in table: */
		if (fd_table_nb_entries < FDSERVER_MAX_ENTRIES) {
			fd_table[fd_table_nb_entries].context = context;
			fd_table[fd_table_nb_entries].key     = key;
			fd_table[fd_table_nb_entries++].fd    = fd;
			ODP_DBG_LVL(FD_DBG, "storing {ctx=%d, key=%" PRIu64 "}->fd=%d\n",
				    context, key, fd);
		} else {
			_ODP_ERR("FD table full\n");
			send_fdserver_msg(client_sock, FD_REGISTER_NACK,
					  FD_SRV_CTX_NA, 0, -1);
			return 0;
		}

		send_fdserver_msg(client_sock, FD_REGISTER_ACK,
				  FD_SRV_CTX_NA, 0, -1);
		break;

	case FD_LOOKUP_REQ:
		if (context >= FD_SRV_CTX_END) {
			_ODP_ERR("invalid lookup context\n");
			send_fdserver_msg(client_sock, FD_LOOKUP_NACK,
					  FD_SRV_CTX_NA, 0, -1);
			return 0;
		}

		/* search key in table and sent reply: */
		for (i = 0; i < fd_table_nb_entries; i++) {
			if ((fd_table[i].context == context) &&
			    (fd_table[i].key == key)) {
				fd = fd_table[i].fd;
				_ODP_DBG("lookup {ctx=%d,"
					" key=%" PRIu64 "}->fd=%d\n",
					context, key, fd);
				send_fdserver_msg(client_sock,
						  FD_LOOKUP_ACK, context, key,
						  fd);
				return 0;
			}
		}

		/* context+key not found... send nack */
		send_fdserver_msg(client_sock, FD_LOOKUP_NACK, context, key,
				  -1);
		break;

	case FD_DEREGISTER_REQ:
		if (context >= FD_SRV_CTX_END) {
			_ODP_ERR("invalid deregister context\n");
			send_fdserver_msg(client_sock, FD_DEREGISTER_NACK,
					  FD_SRV_CTX_NA, 0, -1);
			return 0;
		}

		/* search key in table and remove it if found, and reply: */
		for (i = 0; i < fd_table_nb_entries; i++) {
			if ((fd_table[i].context == context) &&
			    (fd_table[i].key == key)) {
				ODP_DBG_LVL(FD_DBG, "drop {ctx=%d,"
					    " key=%" PRIu64 "}->fd=%d\n",
					   context, key, fd_table[i].fd);
				close(fd_table[i].fd);
				fd_table[i] = fd_table[--fd_table_nb_entries];
				send_fdserver_msg(client_sock,
						  FD_DEREGISTER_ACK,
						  context, key, -1);
				return 0;
			}
		}

		/* key not found... send nack */
		send_fdserver_msg(client_sock, FD_DEREGISTER_NACK,
				  context, key, -1);
		break;

	case FD_SERVERSTOP_REQ:
		ODP_DBG_LVL(FD_DBG, "Stopping FD server\n");
		return 1;

	default:
		_ODP_ERR("Unexpected request\n");
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
	int c_socket; /* client connection */
	unsigned int addr_sz;
	struct sockaddr_un remote;

	for (;;) {
		addr_sz = sizeof(remote);
		c_socket = accept(sock, (struct sockaddr *)&remote, &addr_sz);
		if (c_socket == -1) {
			if (errno == EINTR)
				continue;

			_ODP_ERR("accept() failed: %s\n", strerror(errno));
			return;
		}

		if (handle_request(c_socket))
			break;
		close(c_socket);
	}
	close(c_socket);
}

/*
 * Create a unix domain socket and fork a process to listen to incoming
 * requests.
 */
int _odp_fdserver_init_global(void)
{
	char sockpath[FDSERVER_SOCKPATH_MAXLEN];
	int sock;
	struct sockaddr_un local;
	pid_t server_pid;
	int len, res;

	snprintf(sockpath, FDSERVER_SOCKPATH_MAXLEN, FDSERVER_SOCKDIR_FORMAT,
		 odp_global_ro.shm_dir,
		 odp_global_ro.uid);

	res = mkdir(sockpath, 0744);
	if (res && errno != EEXIST) {
		_ODP_ERR("Could not create directory %s: %s\n", sockpath, strerror(errno));
		return -1;
	}

	/* construct the server named socket path: */
	len = snprintf(sockpath, FDSERVER_SOCKPATH_MAXLEN, FDSERVER_SOCK_FORMAT,
		       odp_global_ro.shm_dir, odp_global_ro.uid,
		       odp_global_ro.main_pid);

	if (len >= FDSERVER_SOCKPATH_MAXLEN || len >= (int)sizeof(local.sun_path)) {
		_ODP_ERR("path too long\n");
		return -1;
	}

	/* create UNIX domain socket: */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		_ODP_ERR("socket() failed: %s\n", strerror(errno));
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
		_ODP_ERR("bind() failed: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	/* listen for incoming connections: */
	if (listen(sock, FDSERVER_BACKLOG) == -1) {
		_ODP_ERR("listen() failed: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	/*
	 * Flush stdio buffers before fork so that the same buffered
	 * data does not end up in both the parent and the child
	 * process and eventually get written out twice.
	 */
	fflush(stdout);
	fflush(stderr);
	/* fork a server process: */
	server_pid = fork();
	if (server_pid == -1) {
		_ODP_ERR("Could not fork!\n");
		close(sock);
		return -1;
	}

	if (server_pid == 0) { /*child */
		sigset_t sigset;
		struct sigaction action;

		/*
		 * Flush again in case someone wrote something between
		 * the first flush and fork. The data is already duplicate
		 * at this point, but it is probably less confusing to output
		 * it now rather than sometime later (probably at fdserver
		 * termination time).
		 */
		fflush(stdout);
		fflush(stderr);

		sigfillset(&sigset);
		/* undefined if these are ignored, as per POSIX */
		(void)sigdelset(&sigset, SIGFPE);
		(void)sigdelset(&sigset, SIGILL);
		(void)sigdelset(&sigset, SIGSEGV);
		/* can not be masked */
		(void)sigdelset(&sigset, SIGKILL);
		(void)sigdelset(&sigset, SIGSTOP);
		/* these we want to handle */
		(void)sigdelset(&sigset, SIGTERM);
		if (sigprocmask(SIG_SETMASK, &sigset, NULL) == -1) {
			_ODP_ERR("Could not set signal mask");
			exit(1);
		}

		/* set default handlers for those signals we can handle */
		memset(&action, 0, sizeof(action));
		action.sa_handler = SIG_DFL;
		sigemptyset(&action.sa_mask);
		action.sa_flags = 0;
		(void)sigaction(SIGFPE, &action, NULL);
		(void)sigaction(SIGILL, &action, NULL);
		(void)sigaction(SIGSEGV, &action, NULL);
		(void)sigaction(SIGTERM, &action, NULL);

		/* TODO: pin the server on appropriate service cpu mask */
		/* when (if) we can agree on the usage of service mask  */

		/* request to be killed if parent dies, hence avoiding  */
		/* orphans being "adopted" by the init process...	*/
		prctl(PR_SET_PDEATHSIG, SIGTERM);

		res = setsid();
		if (res == -1) {
			_ODP_ERR("Could not setsid()");
			exit(1);
		}

		/* allocate the space for the file descriptor<->key table: */
		fd_table = malloc(FDSERVER_MAX_ENTRIES * sizeof(fdentry_t));
		if (!fd_table) {
			_ODP_ERR("malloc() failed!\n");
			exit(1);
		}

		/* wait for clients requests */
		wait_requests(sock); /* Returns when server is stopped  */
		close(sock);

		/* release the file descriptor table: */
		free(fd_table);

		exit(0);
	}

	/* parent */
	odp_global_ro.fdserver_pid = server_pid;
	close(sock);
	return 0;
}

/*
 * Terminate the server
 */
int _odp_fdserver_term_global(void)
{
	int status;
	pid_t pid;
	char sockpath[FDSERVER_SOCKPATH_MAXLEN];

	/* close fdserver and wait for it to terminate */
	if (stop_server()) {
		_ODP_ERR("Server stop failed\n");
		return -1;
	}

	_ODP_DBG("Waiting for fdserver (%i) to stop\n", odp_global_ro.fdserver_pid);
	pid = waitpid(odp_global_ro.fdserver_pid, &status, 0);

	if (pid != odp_global_ro.fdserver_pid)
		_ODP_ERR("Failed to wait for fdserver\n");

	/* construct the server named socket path: */
	snprintf(sockpath, FDSERVER_SOCKPATH_MAXLEN, FDSERVER_SOCK_FORMAT,
		 odp_global_ro.shm_dir,
		 odp_global_ro.uid,
		 odp_global_ro.main_pid);

	/* delete the UNIX domain socket: */
	unlink(sockpath);

	/* delete shm files directory */
	snprintf(sockpath, FDSERVER_SOCKPATH_MAXLEN, FDSERVER_SOCKDIR_FORMAT,
		 odp_global_ro.shm_dir,
		 odp_global_ro.uid);
	rmdir(sockpath);

	return 0;
}
