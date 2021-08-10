/* Copyright (c) 2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/helper/cli.h>
#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <libcli.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <strings.h>

/* Socketpair socket roles. */
enum {
	SP_READ = 0,
	SP_WRITE = 1,
};

#define MAX_NAME_LEN 20
#define MAX_HELP_LEN 100

typedef struct {
	odph_cli_user_cmd_func_t fn;
	char name[MAX_NAME_LEN];
	char help[MAX_HELP_LEN];
} user_cmd_t;

typedef struct {
	volatile int cli_fd;
	/* Server thread will exit if this is false. */
	volatile int run;
	/* Socketpair descriptors. */
	int sp[2];
	int listen_fd;
	/* Guards cli_fd and run, which must be accessed atomically. */
	odp_spinlock_t lock;
	odp_spinlock_t api_lock;
	odph_thread_t thr_server;
	odp_instance_t instance;
	struct sockaddr_in addr;
	uint32_t max_user_commands;
	uint32_t num_user_commands;
	user_cmd_t user_cmd[0];
} cli_shm_t;

static const char *shm_name = "_odp_cli";

static const odph_cli_param_t param_default = {
	.address = "127.0.0.1",
	.port = 55555,
	.max_user_commands = 50,
};

void odph_cli_param_init(odph_cli_param_t *param)
{
	*param = param_default;
}

static cli_shm_t *shm_lookup(void)
{
	cli_shm_t *shm = NULL;
	odp_shm_t shm_hdl = odp_shm_lookup(shm_name);

	if (shm_hdl != ODP_SHM_INVALID)
		shm = (cli_shm_t *)odp_shm_addr(shm_hdl);

	return shm;
}

int odph_cli_init(odp_instance_t instance, const odph_cli_param_t *param)
{
	if (odp_shm_lookup(shm_name) != ODP_SHM_INVALID) {
		ODPH_ERR("Error: shm %s already exists\n", shm_name);
		return -1;
	}

	cli_shm_t *shm = NULL;
	int shm_size = sizeof(cli_shm_t) +
		param->max_user_commands * sizeof(user_cmd_t);
	odp_shm_t shm_hdl =
		odp_shm_reserve(shm_name, shm_size, 64, ODP_SHM_SW_ONLY);

	if (shm_hdl != ODP_SHM_INVALID)
		shm = (cli_shm_t *)odp_shm_addr(shm_hdl);

	if (!shm) {
		ODPH_ERR("Error: failed to reserve shm %s\n", shm_name);
		return -1;
	}

	memset(shm, 0, shm_size);
	odp_spinlock_init(&shm->lock);
	odp_spinlock_init(&shm->api_lock);
	shm->sp[SP_READ] = -1;
	shm->sp[SP_WRITE] = -1;
	shm->listen_fd = -1;
	shm->cli_fd = -1;
	shm->instance = instance;

	shm->addr.sin_family = AF_INET;
	shm->addr.sin_port = htons(param->port);

	switch (inet_pton(AF_INET, param->address, &shm->addr.sin_addr)) {
	case -1:
		ODPH_ERR("Error: inet_pton(): %s\n", strerror(errno));
		return -1;
	case 0:
		ODPH_ERR("Error: inet_pton(): illegal address format\n");
		return -1;
	default:
		break;
	}

	shm->max_user_commands = param->max_user_commands;

	return 0;
}

int odph_cli_register_command(const char *name, odph_cli_user_cmd_func_t func,
			      const char *help)
{
	cli_shm_t *shm = shm_lookup();

	if (!shm) {
		ODPH_ERR("Error: shm %s not found\n", shm_name);
		return -1;
	}

	odp_spinlock_lock(&shm->api_lock);

	odp_spinlock_lock(&shm->lock);
	if (shm->run) {
		odp_spinlock_unlock(&shm->lock);
		ODPH_ERR("Error: cannot register commands while cli server is running\n");
		goto error;
	}
	odp_spinlock_unlock(&shm->lock);

	if (shm->num_user_commands >= shm->max_user_commands) {
		ODPH_ERR("Error: maximum number of user commands already registered\n");
		goto error;
	}

	user_cmd_t *cmd = &shm->user_cmd[shm->num_user_commands];

	cmd->fn = func;

	if (strlen(name) >= MAX_NAME_LEN - 1) {
		ODPH_ERR("Error: command name too long\n");
		goto error;
	}
	strcpy(cmd->name, name);

	if (strlen(help) >= MAX_HELP_LEN - 1) {
		ODPH_ERR("Error: command help too long\n");
		goto error;
	}
	strcpy(cmd->help, help);

	shm->num_user_commands++;
	odp_spinlock_unlock(&shm->api_lock);
	return 0;

error:
	odp_spinlock_unlock(&shm->api_lock);
	return -1;
}

/*
 * Check that number of given arguments matches required number of
 * arguments. Print error messages if this is not the case. Return 0
 * on success, -1 otherwise.
 */
static int check_num_args(struct cli_def *cli, int argc, int req_argc)
{
	if (argc < req_argc) {
		cli_error(cli, "%% Incomplete command.");
		return -1;
	}

	if (argc > req_argc) {
		cli_error(cli, "%% Extra parameter given to command.");
		return -1;
	}

	return 0;
}

static int cmd_call_odp_cls_print_all(struct cli_def *cli,
				      const char *command ODP_UNUSED,
				      char *argv[] ODP_UNUSED, int argc)
{
	if (check_num_args(cli, argc, 0))
		return CLI_ERROR;

	odp_cls_print_all();

	return CLI_OK;
}

static int cmd_call_odp_ipsec_print(struct cli_def *cli,
				    const char *command ODP_UNUSED,
				    char *argv[] ODP_UNUSED, int argc)
{
	if (check_num_args(cli, argc, 0))
		return CLI_ERROR;

	odp_ipsec_print();

	return CLI_OK;
}

static int cmd_call_odp_shm_print_all(struct cli_def *cli,
				      const char *command ODP_UNUSED,
				      char *argv[] ODP_UNUSED, int argc)
{
	if (check_num_args(cli, argc, 0))
		return CLI_ERROR;

	odp_shm_print_all();

	return CLI_OK;
}

static int cmd_call_odp_sys_config_print(struct cli_def *cli,
					 const char *command ODP_UNUSED,
					 char *argv[] ODP_UNUSED, int argc)
{
	if (check_num_args(cli, argc, 0))
		return CLI_ERROR;

	odp_sys_config_print();

	return CLI_OK;
}

static int cmd_call_odp_sys_info_print(struct cli_def *cli,
				       const char *command ODP_UNUSED,
				       char *argv[] ODP_UNUSED, int argc)
{
	if (check_num_args(cli, argc, 0))
		return CLI_ERROR;

	odp_sys_info_print();

	return CLI_OK;
}

static int cmd_call_odp_pktio_print(struct cli_def *cli,
				    const char *command ODP_UNUSED,
				    char *argv[], int argc)
{
	if (check_num_args(cli, argc, 1))
		return CLI_ERROR;

	odp_pktio_t hdl = odp_pktio_lookup(argv[0]);

	if (hdl == ODP_PKTIO_INVALID) {
		cli_error(cli, "%% Name not found.");
		return CLI_ERROR;
	}

	odp_pktio_print(hdl);

	return CLI_OK;
}

static int cmd_call_odp_pool_print(struct cli_def *cli,
				   const char *command ODP_UNUSED, char *argv[],
				   int argc)
{
	if (check_num_args(cli, argc, 1))
		return CLI_ERROR;

	odp_pool_t hdl = odp_pool_lookup(argv[0]);

	if (hdl == ODP_POOL_INVALID) {
		cli_error(cli, "%% Name not found.");
		return CLI_ERROR;
	}

	odp_pool_print(hdl);

	return CLI_OK;
}

static int cmd_call_odp_queue_print(struct cli_def *cli,
				    const char *command ODP_UNUSED,
				    char *argv[], int argc)
{
	if (check_num_args(cli, argc, 1))
		return CLI_ERROR;

	odp_queue_t hdl = odp_queue_lookup(argv[0]);

	if (hdl == ODP_QUEUE_INVALID) {
		cli_error(cli, "%% Name not found.");
		return CLI_ERROR;
	}

	odp_queue_print(hdl);

	return CLI_OK;
}

static int cmd_call_odp_queue_print_all(struct cli_def *cli,
					const char *command ODP_UNUSED,
					char *argv[] ODP_UNUSED, int argc)
{
	if (check_num_args(cli, argc, 0))
		return CLI_ERROR;

	odp_queue_print_all();

	return CLI_OK;
}

static int cmd_call_odp_shm_print(struct cli_def *cli,
				  const char *command ODP_UNUSED, char *argv[],
				  int argc)
{
	if (check_num_args(cli, argc, 1))
		return CLI_ERROR;

	odp_shm_t hdl = odp_shm_lookup(argv[0]);

	if (hdl == ODP_SHM_INVALID) {
		cli_error(cli, "%% Name not found.");
		return CLI_ERROR;
	}

	odp_shm_print(hdl);

	return CLI_OK;
}

static int cmd_user_cmd(struct cli_def *cli ODP_UNUSED, const char *command,
			char *argv[], int argc)
{
	cli_shm_t *shm = shm_lookup();

	if (!shm) {
		ODPH_ERR("Error: shm %s not found\n", shm_name);
		return CLI_ERROR;
	}

	for (uint32_t i = 0; i < shm->num_user_commands; i++) {
		if (!strcasecmp(command, shm->user_cmd[i].name)) {
			shm->user_cmd[i].fn(argc, argv);
			break;
		}
	}

	return CLI_OK;
}

static struct cli_def *create_cli(cli_shm_t *shm)
{
	struct cli_command *c;
	struct cli_def *cli;

	cli = cli_init();
	cli_set_banner(cli, NULL);
	cli_set_hostname(cli, "ODP");

	c = cli_register_command(cli, NULL, "call", NULL,
				 PRIVILEGE_UNPRIVILEGED, MODE_EXEC,
				 "Call ODP API function.");
	cli_register_command(cli, c, "odp_cls_print_all",
			     cmd_call_odp_cls_print_all,
			     PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "odp_ipsec_print",
			     cmd_call_odp_ipsec_print,
			     PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "odp_pktio_print",
			     cmd_call_odp_pktio_print,
			     PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "<name>");
	cli_register_command(cli, c, "odp_pool_print",
			     cmd_call_odp_pool_print,
			     PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "<name>");
	cli_register_command(cli, c, "odp_queue_print",
			     cmd_call_odp_queue_print,
			     PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "<name>");
	cli_register_command(cli, c, "odp_queue_print_all",
			     cmd_call_odp_queue_print_all,
			     PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "odp_shm_print_all",
			     cmd_call_odp_shm_print_all,
			     PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "odp_shm_print",
			     cmd_call_odp_shm_print,
			     PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "<name>");
	cli_register_command(cli, c, "odp_sys_config_print",
			     cmd_call_odp_sys_config_print,
			     PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "odp_sys_info_print",
			     cmd_call_odp_sys_info_print,
			     PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);

	for (uint32_t i = 0; i < shm->num_user_commands; i++) {
		cli_register_command(cli, NULL, shm->user_cmd[i].name,
				     cmd_user_cmd, PRIVILEGE_UNPRIVILEGED,
				     MODE_EXEC, shm->user_cmd[i].help);
	}

	return cli;
}

/* Not shared, used only in the server thread. */
static struct cli_def *cli;
static char *cli_log_fn_buf;

ODP_PRINTF_FORMAT(2, 0)
static int cli_log_va(odp_log_level_t level, const char *fmt, va_list in_args)
{
	(void)level;

	va_list args;
	char *str, *p, *last;
	int len;

	/*
	 * This function should be just a simple call to cli_vabufprint().
	 * Unfortunately libcli (at least versions 1.9.7 - 1.10.4) has a few
	 * bugs. cli_print() prints a newline at the end even if the string
	 * doesn't end in a newline. cli_*bufprint() on the other hand just
	 * throws away everything after the last newline.
	 *
	 * The following code ensures that each cli_*print() ends in a newline.
	 * If the string does not end in a newline, we keep the part of the
	 * string after the last newline and use it the next time we're called.
	 */
	va_copy(args, in_args);
	len = vsnprintf(NULL, 0, fmt, args) + 1;
	va_end(args);
	str = malloc(len);

	if (!str) {
		ODPH_ERR("malloc failed\n");
		return -1;
	}

	va_copy(args, in_args);
	vsnprintf(str, len, fmt, args);
	va_end(args);
	p = str;
	last = strrchr(p, '\n');

	if (last) {
		*last++ = 0;
		if (cli_log_fn_buf) {
			cli_bufprint(cli, "%s%s\n", cli_log_fn_buf, p);
			free(cli_log_fn_buf);
			cli_log_fn_buf = NULL;
		} else {
			cli_bufprint(cli, "%s\n", p);
		}
		p = last;
	}

	if (*p) {
		if (cli_log_fn_buf) {
			char *buffer_new =
				malloc(strlen(cli_log_fn_buf) + strlen(p) + 1);

			if (!buffer_new) {
				ODPH_ERR("malloc failed\n");
				goto out;
			}

			strcpy(buffer_new, cli_log_fn_buf);
			strcat(buffer_new, p);
			free(cli_log_fn_buf);
			cli_log_fn_buf = buffer_new;
		} else {
			cli_log_fn_buf = malloc(strlen(p) + 1);

			if (!cli_log_fn_buf) {
				ODPH_ERR("malloc failed\n");
				goto out;
			}

			strcpy(cli_log_fn_buf, p);
		}
	}

out:
	free(str);

	return len;
}

ODP_PRINTF_FORMAT(2, 3)
static int cli_log(odp_log_level_t level, const char *fmt, ...)
{
	(void)level;

	int r;
	va_list args;

	va_start(args, fmt);
	r = cli_log_va(level, fmt, args);
	va_end(args);

	return r;
}

ODP_PRINTF_FORMAT(1, 2)
int odph_cli_log(const char *fmt, ...)
{
	int r;
	va_list args;

	va_start(args, fmt);
	r = cli_log_va(ODP_LOG_PRINT, fmt, args);
	va_end(args);

	return r;
}

static int cli_server(void *arg ODP_UNUSED)
{
	cli_shm_t *shm = shm_lookup();

	if (!shm) {
		ODPH_ERR("Error: shm %s not found\n", shm_name);
		return -1;
	}

	cli = create_cli(shm);

	while (1) {
		struct pollfd pfd[2] = {
			{ .fd = shm->sp[SP_READ], .events = POLLIN, },
			{ .fd = shm->listen_fd, .events = POLLIN, },
		};

		if (poll(pfd, 2, -1) < 0) {
			ODPH_ERR("Error: poll(): %s\n", strerror(errno));
			break;
		}

		/*
		 * If we have an event on a socketpair socket, it's
		 * time to exit.
		 */
		if (pfd[0].revents)
			break;

		/*
		 * If we don't have an event on the listening socket, poll
		 * again.
		 */
		if (!pfd[1].revents)
			continue;

		int fd = accept(shm->listen_fd, NULL, 0);

		if (fd < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;

			ODPH_ERR("Error: accept(): %s\n", strerror(errno));
			break;
		}

		/*
		 * The only way to stop cli_loop() is to close the socket, after
		 * which cli_loop() gets an error on the next select() and then
		 * calls close() before returning. This is a problem because the
		 * fd may be reused before the select() or the final close().
		 *
		 * To avoid this problem, switch to a higher fd number
		 * (select() maximum). We will still run into problems if the
		 * descriptor numbers in the process reach FD_SETSIZE - 1 =
		 * 1023.
		 */
		int newfd = dup2(fd, FD_SETSIZE - 1);

		if (newfd < 0) {
			ODPH_ERR("Error: dup2(): %s\n", strerror(errno));
			close(fd);
			continue;
		}

		close(fd);
		fd = newfd;

		odp_spinlock_lock(&shm->lock);
		if (!shm->run) {
			odp_spinlock_unlock(&shm->lock);
			/*
			 * odph_cli_stop() has been called. Close the
			 * socket we just accepted and exit.
			 */
			close(fd);
			break;
		}
		shm->cli_fd = fd;
		odp_spinlock_unlock(&shm->lock);

		odp_log_thread_fn_set(cli_log);
		/*
		 * cli_loop() returns only when client is disconnected. One
		 * possible reason for disconnect is odph_cli_stop().
		 */
		cli_loop(cli, shm->cli_fd);
		odp_log_thread_fn_set(NULL);

		odp_spinlock_lock(&shm->lock);
		/*
		 * cli_loop() closes the socket before returning (undocumented).
		 */
		shm->cli_fd = -1;
		odp_spinlock_unlock(&shm->lock);

		/*
		 * Throw away anything left in the buffer (in case the last
		 * print didn't end in a newline).
		 */
		free(cli_log_fn_buf);
		cli_log_fn_buf = NULL;
	}

	cli_done(cli);

	return 0;
}

int odph_cli_start(void)
{
	cli_shm_t *shm = shm_lookup();

	if (!shm) {
		ODPH_ERR("Error: shm %s not found\n", shm_name);
		return -1;
	}

	odp_spinlock_lock(&shm->api_lock);
	odp_spinlock_lock(&shm->lock);
	if (shm->run) {
		odp_spinlock_unlock(&shm->lock);
		odp_spinlock_unlock(&shm->api_lock);
		ODPH_ERR("Error: cli server has already been started\n");
		return -1;
	}
	shm->run = 1;
	shm->cli_fd = -1;
	odp_spinlock_unlock(&shm->lock);

	shm->sp[SP_READ] = -1;
	shm->sp[SP_WRITE] = -1;
	shm->listen_fd = -1;

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, shm->sp)) {
		ODPH_ERR("Error: socketpair(): %s\n", strerror(errno));
		goto error;
	}

	/* Create listening socket. */

	shm->listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (shm->listen_fd < 0) {
		ODPH_ERR("Error: socket(): %s\n", strerror(errno));
		goto error;
	}

	int on = 1;

	if (setsockopt(shm->listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
		ODPH_ERR("Error: setsockopt(): %s\n", strerror(errno));
		goto error;
	}

	if (bind(shm->listen_fd, (struct sockaddr *)&shm->addr,
		 sizeof(shm->addr))) {
		ODPH_ERR("Error: bind(): %s\n", strerror(errno));
		goto error;
	}

	if (listen(shm->listen_fd, 1)) {
		ODPH_ERR("Error: listen(): %s\n", strerror(errno));
		goto error;
	}

	/* Create server thread. */

	odp_cpumask_t cpumask;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;

	if (odp_cpumask_default_control(&cpumask, 1) != 1) {
		ODPH_ERR("Error: odp_cpumask_default_control() failed\n");
		goto error;
	}

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = shm->instance;
	thr_common.cpumask = &cpumask;

	odph_thread_param_init(&thr_param);
	thr_param.thr_type = ODP_THREAD_CONTROL;
	thr_param.start = cli_server;

	memset(&shm->thr_server, 0, sizeof(shm->thr_server));

	if (odph_thread_create(&shm->thr_server, &thr_common, &thr_param, 1) != 1) {
		ODPH_ERR("Error: odph_thread_create() failed\n");
		goto error;
	}

	odp_spinlock_unlock(&shm->api_lock);
	return 0;

error:
	shm->run = 0;
	if (shm->sp[SP_READ] >= 0)
		close(shm->sp[SP_READ]);
	if (shm->sp[SP_WRITE] >= 0)
		close(shm->sp[SP_WRITE]);
	if (shm->listen_fd >= 0)
		close(shm->listen_fd);
	if (shm->cli_fd >= 0)
		close(shm->cli_fd);
	odp_spinlock_unlock(&shm->api_lock);
	return -1;
}

int odph_cli_stop(void)
{
	cli_shm_t *shm = shm_lookup();

	if (!shm) {
		ODPH_ERR("Error: shm %s not found\n", shm_name);
		return -1;
	}

	odp_spinlock_lock(&shm->api_lock);
	odp_spinlock_lock(&shm->lock);
	if (!shm->run) {
		odp_spinlock_unlock(&shm->lock);
		odp_spinlock_unlock(&shm->api_lock);
		ODPH_ERR("Error: cli server has not been started\n");
		return -1;
	}
	shm->run = 0;
	/*
	 * Close the current cli connection. This stops cli_loop(). If cli
	 * client is disconnecting at the same time, cli_fd may already have
	 * been closed.
	 */
	if (shm->cli_fd >= 0) {
		close(shm->cli_fd);
		shm->cli_fd = -1;
	}
	odp_spinlock_unlock(&shm->lock);

	/*
	 * Send a message to the server thread in order to break it out of a
	 * blocking poll() call.
	 */
	int stop = 1;
	int sent = send(shm->sp[SP_WRITE], &stop,
			sizeof(stop), MSG_DONTWAIT | MSG_NOSIGNAL);

	if (sent != sizeof(stop)) {
		ODPH_ERR("Error: send() = %d: %s\n", sent, strerror(errno));
		goto error;
	}

	if (odph_thread_join(&shm->thr_server, 1) != 1) {
		ODPH_ERR("Error: odph_thread_join() failed\n");
		goto error;
	}

	close(shm->sp[SP_READ]);
	close(shm->sp[SP_WRITE]);
	close(shm->listen_fd);
	odp_spinlock_unlock(&shm->api_lock);
	return 0;

error:
	odp_spinlock_unlock(&shm->api_lock);
	return -1;
}

int odph_cli_term(void)
{
	cli_shm_t *shm = NULL;
	odp_shm_t shm_hdl = odp_shm_lookup(shm_name);

	if (shm_hdl != ODP_SHM_INVALID)
		shm = (cli_shm_t *)odp_shm_addr(shm_hdl);

	if (!shm) {
		ODPH_ERR("Error: shm %s not found\n", shm_name);
		return -1;
	}

	if (odp_shm_free(shm_hdl)) {
		ODPH_ERR("Error: odp_shm_free() failed\n");
		return -1;
	}

	return 0;
}
