/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define S_(x) #x
#define S(x) S_(x)
#define MAX_PROGS 8
#define CMD_DELIMITER ","
#define PROG_NAME "odp_dyn_workers"

#define FOREACH_CMD(CMD) \
	CMD(ADD_WORKER) \
	CMD(REM_WORKER)

#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,
#define ADDITION 'a'
#define REMOVAL 'r'
#define DELAY 'd'
#define IDX_DELIMITER ":"
#define MAX_NIBBLE 15
#define MAX_WORKERS MAX_NIBBLE
#define MAX_PATTERN_LEN 32U
#define ENV_PREFIX "ODP"
#define ENV_DELIMITER "="
#define UNKNOWN_CMD MAX_NIBBLE
#define EXIT_PROG (UNKNOWN_CMD - 1U)
#define DELAY_PROG (EXIT_PROG - 1U)

ODP_STATIC_ASSERT(MAX_WORKERS <= MAX_NIBBLE, "Too many workers");

enum {
	FOREACH_CMD(GENERATE_ENUM)
};

typedef enum {
	PRS_OK,
	PRS_NOK,
	PRS_TERM
} parse_result_t;

enum {
	PARENT,
	CHILD
};

typedef enum {
	DOWN,
	UP
} state_t;

enum {
	CONN_ERR = -1,
	PEER_ERR,
	CMD_NOK,
	CMD_SUMMARY,
	CMD_OK
};

static const char *const cmdstrs[] = {
	FOREACH_CMD(GENERATE_STRING)
};

ODP_STATIC_ASSERT(ODPH_ARRAY_SIZE(cmdstrs) < DELAY_PROG, "Too many commands");

typedef struct {
	uint64_t thread_id;
	uint64_t num_handled;
	uint64_t enq_errs;
	uint64_t runtime;
} summary_t;

typedef struct prog_t {
	summary_t summary;
	char *env;
	char *cpumask;
	pid_t pid;
	int socket;
	state_t state;
} prog_t;

typedef struct {
	uint64_t val1;
	uint8_t val2;
	uint8_t op;
} pattern_t;

typedef struct {
	pattern_t pattern[MAX_PATTERN_LEN];
	prog_t progs[MAX_PROGS];
	uint32_t num_p_elems;
	uint32_t num_progs;
	uint32_t max_cmd_len;
	odp_bool_t is_running;
} global_config_t;

typedef struct worker_config_s worker_config_t;

typedef struct worker_config_s {
	odph_thread_t thread;
	odp_barrier_t barrier;
	summary_t summary;
	odp_ticketlock_t lock;
	odp_schedule_group_t grp;
	odp_queue_t queue;
	worker_config_t *configs;
	odp_atomic_u32_t is_running;
	uint8_t idx;
} worker_config_t;

typedef struct {
	worker_config_t worker_config[MAX_WORKERS];
	odp_instance_t instance;
	odp_cpumask_t cpumask;
	odp_pool_t pool;
	summary_t *pending_summary;
	uint32_t num_workers;
	int socket;
} prog_config_t;

typedef struct {
	struct {
		uint16_t is_active;
		uint16_t cpu;
		uint32_t thread_id;
	} workers[MAX_WORKERS];
} result_t;

typedef odp_bool_t (*input_fn_t)(global_config_t *config, uint8_t *cmd, uint32_t *prog_idx,
				 uint32_t *worker_idx);
typedef odp_bool_t (*cmd_fn_t)(prog_config_t *config, uint8_t aux);

static global_config_t conf;
static prog_config_t *prog_conf;

static void terminate(int signal ODP_UNUSED)
{
	conf.is_running = false;
}

static odp_bool_t setup_signals(void)
{
	struct sigaction action = { .sa_handler = terminate };

	if (sigemptyset(&action.sa_mask) == -1 || sigaddset(&action.sa_mask, SIGINT) == -1 ||
	    sigaddset(&action.sa_mask, SIGTERM) == -1 ||
	    sigaddset(&action.sa_mask, SIGHUP) == -1 || sigaction(SIGINT, &action, NULL) == -1 ||
	    sigaction(SIGTERM, &action, NULL) == -1 || sigaction(SIGHUP, &action, NULL) == -1)
		return false;

	return true;
}

static void init_options(global_config_t *config)
{
	uint32_t max_len = 0U, str_len;

	memset(config, 0, sizeof(*config));

	for (uint32_t i = 0U; i < ODPH_ARRAY_SIZE(cmdstrs); ++i) {
		str_len = strlen(cmdstrs[i]);

		if (str_len > max_len)
			max_len = str_len;
	}

	config->max_cmd_len = max_len;
}

static void parse_masks(global_config_t *config, const char *optarg)
{
	char *tmp_str = strdup(optarg), *tmp;
	prog_t *prog;

	if (tmp_str == NULL)
		return;

	tmp = strtok(tmp_str, CMD_DELIMITER);

	while (tmp && config->num_progs < MAX_PROGS) {
		prog = &config->progs[config->num_progs];
		prog->cpumask = strdup(tmp);

		if (prog->cpumask != NULL)
			++config->num_progs;

		tmp = strtok(NULL, CMD_DELIMITER);
	}

	free(tmp_str);
}

static void parse_pattern(global_config_t *config, const char *optarg)
{
	char *tmp_str = strdup(optarg), *tmp, op;
	uint8_t num_elems = 0U;
	pattern_t *pattern;
	uint64_t val1;
	uint32_t val2;
	int ret;

	if (tmp_str == NULL)
		return;

	tmp = strtok(tmp_str, CMD_DELIMITER);

	while (tmp && num_elems < MAX_PATTERN_LEN) {
		pattern = &config->pattern[num_elems];
		/* Use invalid values to prevent correct values by chance. */
		val1 = -1;
		val2 = -1;
		ret = sscanf(tmp, "%c%" PRIu64 IDX_DELIMITER "%u", &op, &val1, &val2);

		if ((ret == 2 || ret == 3) && (op == ADDITION || op == REMOVAL || op == DELAY)) {
			pattern->val1 = val1;
			pattern->val2 = val2;
			pattern->op = op;
			++num_elems;
		}

		tmp = strtok(NULL, CMD_DELIMITER);
	}

	free(tmp_str);
	config->num_p_elems = num_elems;
}

static void print_usage(void)
{
	printf("\n"
	       "Simple interactive ODP dynamic worker tester. Can be used to verify ability of\n"
	       "an implementation to dynamically add and remove workers from one ODP application\n"
	       "to another. Acts as a frontend and forks ODP applications based on\n"
	       "configuration.\n"
	       "\n"
	       "Usage: " PROG_NAME " OPTIONS\n"
	       "\n"
	       "  E.g. ODP0=MY_ENV=MY_VAL ODP1=MY_ENV=MY_VAL " PROG_NAME " -c 0x80,0x80\n"
	       "       ...\n"
	       "       > %s 0 0\n"
	       "       > %s 0 0\n"
	       "       > %s 1 0\n"
	       "       > %s 1 0\n"
	       "       ...\n"
	       "       " PROG_NAME " -c 0x80,0x80 -p %c0%s0%s%c1000000000%s%c0%s0\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "\n"
	       "  -c, --cpumasks CPU masks for to-be-created ODP processes, comma-separated, no\n"
	       "                 spaces. CPU mask format should be as expected by\n"
	       "                 'odp_cpumask_from_str()'. Parsed amount of CPU masks will be\n"
	       "                 the number of ODP processes to be created. Theoretical maximum\n"
	       "                 number of CPU mask entries (and to-be-created ODP processes) is\n"
	       "                 %u. Theoretical maximum number of workers per ODP process is\n"
	       "                 %u. These might be further limited by the implementation.\n\n"
	       "                 A single environment variable can be passed to the processes.\n"
	       "                 The format should be: 'ODP<x>=<name>=<value>', where <x> is\n"
	       "                 process index, starting from 0.\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "\n"
	       "  -p, --pattern  Non-interactive mode with a pattern of worker additions,\n"
	       "                 removals and delays, delimited by '%s', no spaces. Additions\n"
	       "                 are indicated with '%c' prefix, removals with '%c' prefix, both\n"
	       "                 followed by process index, starting from 0 and worker thread\n"
	       "                 index within given cpumask delimited by '%s', and delays with\n"
	       "                 '%c' prefix, followed by a delay in nanoseconds. Process\n"
	       "                 indexes are based on the parsed process count of '--cpumasks'\n"
	       "                 option. Additions and removals should be equal in the aggregate\n"
	       "                 and removals should never outnumber additions at any instant.\n"
	       "                 Maximum pattern length is %u.\n"
	       "  -h, --help     This help.\n"
	       "\n", cmdstrs[ADD_WORKER], cmdstrs[REM_WORKER], cmdstrs[ADD_WORKER],
	       cmdstrs[REM_WORKER], ADDITION, IDX_DELIMITER, CMD_DELIMITER, DELAY, CMD_DELIMITER,
	       REMOVAL, IDX_DELIMITER, MAX_PROGS, MAX_WORKERS, CMD_DELIMITER, ADDITION, REMOVAL,
	       IDX_DELIMITER, DELAY, MAX_PATTERN_LEN);
}

static parse_result_t check_options(const global_config_t *config)
{
	const pattern_t *pattern;
	int64_t num_tot = 0U;

	if (config->num_progs == 0U || config->num_progs > MAX_PROGS) {
		printf("Invalid number of CPU masks: %u\n", config->num_progs);
		return PRS_NOK;
	}

	for (uint32_t i = 0U; i < config->num_p_elems; ++i) {
		pattern = &config->pattern[i];

		if (pattern->op != DELAY) {
			if (pattern->val1 >= config->num_progs) {
				ODPH_ERR("Invalid pattern, invalid process index: %" PRIu64 "\n",
					 pattern->val1);
				return PRS_NOK;
			}

			if (pattern->val2 > MAX_WORKERS - 1) {
				ODPH_ERR("Invalid pattern, invalid worker index: %u\n",
					 pattern->val2);
				return PRS_NOK;
			}
		}

		if (pattern->op == ADDITION)
			++num_tot;
		else if (pattern->op == REMOVAL)
			--num_tot;

		if (num_tot < 0) {
			ODPH_ERR("Invalid pattern, removals exceed additions instantaneously\n");
			return PRS_NOK;
		}
	}

	if (num_tot > 0) {
		ODPH_ERR("Invalid pattern, more additions than removals\n");
		return PRS_NOK;
	}

	return PRS_OK;
}

static parse_result_t parse_options(int argc, char **argv, global_config_t *config)
{
	int opt;

	static const struct option longopts[] = {
		{ "cpumasks", required_argument, NULL, 'c' },
		{ "pattern", required_argument, NULL, 'p' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "c:p:h";

	init_options(config);

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'c':
			parse_masks(config, optarg);
			break;
		case 'p':
			parse_pattern(config, optarg);
			break;
		case 'h':
			print_usage();
			return PRS_TERM;
		case '?':
		default:
			print_usage();
			return PRS_NOK;
		}
	}

	return check_options(config);
}

static odp_bool_t setup_pkill(pid_t ppid)
{
	return prctl(PR_SET_PDEATHSIG, SIGKILL) != -1 && getppid() == ppid;
}

ODP_PRINTF_FORMAT(2, 3)
int log_fn(odp_log_level_t level, const char *fmt, ...);

int log_fn(odp_log_level_t level, const char *fmt, ...)
{
	int pri;
	va_list args;

	switch (level) {
	case ODP_LOG_DBG:
	case ODP_LOG_PRINT:
		pri = LOG_INFO;
		break;
	case ODP_LOG_WARN:
		pri = LOG_WARNING;
		break;
	case ODP_LOG_ERR:
	case ODP_LOG_UNIMPLEMENTED:
	case ODP_LOG_ABORT:
		pri = LOG_ERR;
		break;
	default:
		pri = LOG_INFO;
		break;
	}

	va_start(args, fmt);
	vsyslog(pri, fmt, args);
	va_end(args);

	/* Just return something that's not considered an error. */
	return 0;
}

static odp_bool_t disable_stream(int fd, odp_bool_t read)
{
	const int null = open("/dev/null", read ? O_RDONLY : O_WRONLY);
	odp_bool_t ret = false;

	if (null == -1)
		return ret;

	ret = dup2(null, fd) != -1;
	close(null);

	return ret;
}

static odp_bool_t set_odp_env(char *env)
{
	char *tmp_str = strdup(env), *tmp;
	int ret;
	odp_bool_t func_ret = false;

	if (tmp_str == NULL)
		return func_ret;

	tmp = strtok(tmp_str, ENV_DELIMITER);

	if (tmp != NULL) {
		ret = setenv(tmp, strstr(env, ENV_DELIMITER) + 1U, 1);

		if (ret == -1)
			perror("setenv");

		func_ret = ret != -1;
	}

	free(tmp_str);

	return func_ret;
}

static odp_bool_t setup_prog_config(prog_config_t *config, odp_instance_t odp_instance,
				    char *cpumask, int socket)
{
	worker_config_t *worker_config;
	odp_pool_param_t param;
	odp_pool_t pool;

	memset(config, 0, sizeof(*config));

	for (uint32_t i = 0U; i < MAX_WORKERS; ++i) {
		worker_config = &config->worker_config[i];
		worker_config->thread.cpu = -1;
		odp_ticketlock_init(&worker_config->lock);
		worker_config->queue = ODP_QUEUE_INVALID;
		odp_atomic_init_u32(&worker_config->is_running, 0U);
	}

	config->instance = odp_instance;
	odp_cpumask_from_str(&config->cpumask, cpumask);
	odp_pool_param_init(&param);
	param.type = ODP_POOL_BUFFER;
	param.buf.num = 1U;
	param.buf.size = ODP_CACHE_LINE_SIZE;
	pool = odp_pool_create(NULL, &param);

	if (pool == ODP_POOL_INVALID) {
		log_fn(ODP_LOG_ERR, "Error creating process buffer pool\n");
		return false;
	}

	config->pool = pool;
	config->socket = socket;

	return true;
}

static inline void decode_cmd(uint8_t data, uint8_t *cmd, uint8_t *aux)
{
	/* Actual command will be in the high nibble and worker index in the low nibble. */
	*cmd = data >> 4U;
	*aux = data & 0xF;
}

static void build_result(const prog_config_t *config, result_t *result)
{
	uint32_t num = 0U;
	const worker_config_t *worker_config;

	for (uint32_t i = 0U; i < MAX_WORKERS; ++i) {
		worker_config = &config->worker_config[i];

		if (worker_config->thread.cpu != -1) {
			result->workers[num].is_active = 1;
			result->workers[num].thread_id = worker_config->summary.thread_id;
			result->workers[num].cpu = worker_config->thread.cpu;
			++num;
		}
	}
}

static void run_command(cmd_fn_t cmd_fn, uint8_t aux, prog_config_t *config, int socket)
{
	const odp_bool_t is_ok = cmd_fn(config, aux);
	const summary_t *summary = config->pending_summary;
	uint8_t rep = !is_ok ? CMD_NOK : summary != NULL ? CMD_SUMMARY : CMD_OK;
	result_t result;

	(void)TEMP_FAILURE_RETRY(send(socket, &rep, sizeof(rep), MSG_NOSIGNAL));

	/* Same machine, no internet in-between, just send the structs as is. */
	if (rep == CMD_OK) {
		memset(&result, 0, sizeof(result));
		build_result(config, &result);
		(void)TEMP_FAILURE_RETRY(send(socket, (const void *)&result, sizeof(result),
					      MSG_NOSIGNAL));
	} else if (rep == CMD_SUMMARY) {
		(void)TEMP_FAILURE_RETRY(send(socket, (const void *)summary, sizeof(*summary),
					      MSG_NOSIGNAL));
		config->pending_summary = NULL;
	}
}

static odp_bool_t setup_worker_config(worker_config_t *config)
{
	odp_thrmask_t tmask;
	odp_schedule_group_t grp;
	odp_queue_param_t queue_param;
	odp_queue_t queue;

	odp_thrmask_zero(&tmask);
	grp = odp_schedule_group_create(NULL, &tmask);

	if (grp == ODP_SCHED_GROUP_INVALID) {
		log_fn(ODP_LOG_ERR, "Error creating scheduler group\n");
		return false;
	}

	config->grp = grp;
	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.group = config->grp;
	queue = odp_queue_create(NULL, &queue_param);

	if (queue == ODP_QUEUE_INVALID) {
		log_fn(ODP_LOG_ERR, "Error creating queue\n");
		(void)odp_schedule_group_destroy(config->grp);
		return false;
	}

	odp_ticketlock_lock(&config->lock);
	config->queue = queue;
	odp_ticketlock_unlock(&config->lock);

	return true;
}

static inline int get_cpu(odp_cpumask_t *mask, int idx)
{
	int cpu = odp_cpumask_first(mask);

	while (idx--) {
		cpu = odp_cpumask_next(mask, cpu);

		if (cpu < 0)
			break;
	}

	return cpu;
}

static odp_bool_t signal_ready(int socket)
{
	uint8_t cmd = CMD_OK;
	ssize_t ret;

	ret = TEMP_FAILURE_RETRY(send(socket, &cmd, sizeof(cmd), MSG_NOSIGNAL));

	if (ret != 1) {
		log_fn(ODP_LOG_ERR, "Error signaling process readiness: %s\n", strerror(errno));
		return false;
	}

	return true;
}

static void enq_to_next_queue(worker_config_t *config, int idx, odp_event_t ev, summary_t *summary)
{
	worker_config_t *worker_config;
	int ret;

	for (uint32_t i = 1U; i <= MAX_WORKERS; ++i) {
		worker_config = &config[(idx + i) % MAX_WORKERS];
		odp_ticketlock_lock(&worker_config->lock);

		if (worker_config->queue == ODP_QUEUE_INVALID) {
			odp_ticketlock_unlock(&worker_config->lock);
			continue;
		}

		ret = odp_queue_enq(worker_config->queue, ev);
		++summary->num_handled;

		if (ret < 0)
			++summary->enq_errs;

		odp_ticketlock_unlock(&worker_config->lock);
		return;
	}

	odp_event_free(ev);
}

static int run_worker(void *args)
{
	odp_time_t tm;
	odp_thrmask_t tmask;
	const int thread_id = odp_thread_id();
	worker_config_t *config = args;
	odp_event_t ev;
	worker_config_t *configs = config->configs;
	summary_t *summary = &config->summary;
	const uint8_t idx = config->idx;

	summary->thread_id = thread_id;
	tm = odp_time_local_strict();
	odp_thrmask_zero(&tmask);
	odp_thrmask_set(&tmask, thread_id);

	if (odp_schedule_group_join(config->grp, &tmask) < 0)
		/* Log but still continue. */
		log_fn(ODP_LOG_ERR, "Error joining scheduler group\n");

	odp_barrier_wait(&config->barrier);

	while (odp_atomic_load_u32(&config->is_running)) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev == ODP_EVENT_INVALID)
			continue;

		enq_to_next_queue(configs, idx, ev, summary);
	}

	while (true) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev == ODP_EVENT_INVALID)
			break;

		enq_to_next_queue(configs, idx, ev, summary);
	}

	summary->runtime = odp_time_diff_ns(odp_time_local_strict(), tm);

	return 0;
}

static void shutdown_worker(worker_config_t *config)
{
	odp_queue_t queue;

	odp_ticketlock_lock(&config->lock);
	queue = config->queue;
	config->queue = ODP_QUEUE_INVALID;
	odp_ticketlock_unlock(&config->lock);

	odp_atomic_store_u32(&config->is_running, 0U);
	(void)odph_thread_join(&config->thread, 1);
	(void)odp_queue_destroy(queue);
	(void)odp_schedule_group_destroy(config->grp);
}

static odp_bool_t bootstrap_scheduling(worker_config_t *config, odp_pool_t pool)
{
	odp_buffer_t buf = odp_buffer_alloc(pool);

	if (buf == ODP_BUFFER_INVALID)
		/* Event still in circulation. */
		return true;

	if (odp_queue_enq(config->queue, odp_buffer_to_event(buf)) < 0) {
		log_fn(ODP_LOG_ERR, "Error enqueueing bootstrap event\n");
		odp_buffer_free(buf);
		shutdown_worker(config);
		return false;
	}

	return true;
}

static odp_bool_t add_worker(prog_config_t *config, uint8_t idx)
{
	worker_config_t *worker_config;
	odph_thread_common_param_t thr_common;
	int set_cpu;
	odp_cpumask_t cpumask;
	odph_thread_param_t thr_param;

	if (config->num_workers == MAX_WORKERS) {
		log_fn(ODP_LOG_WARN, "Maximum number of workers already created\n");
		return false;
	}

	if (idx >= MAX_WORKERS) {
		log_fn(ODP_LOG_ERR, "Worker index out of bounds: %u\n", idx);
		return false;
	}

	worker_config = &config->worker_config[idx];

	if (worker_config->thread.cpu != -1) {
		log_fn(ODP_LOG_WARN, "Worker already created: %u\n", idx);
		return false;
	}

	set_cpu = get_cpu(&config->cpumask, idx);

	if (set_cpu < 0) {
		log_fn(ODP_LOG_ERR, "No CPU found for index: %u\n", idx);
		return false;
	}

	memset(&worker_config->summary, 0, sizeof(worker_config->summary));

	if (!setup_worker_config(worker_config))
		return false;

	worker_config->configs = config->worker_config;
	worker_config->idx = idx;
	odph_thread_common_param_init(&thr_common);
	thr_common.instance = config->instance;

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, set_cpu);
	thr_common.cpumask = &cpumask;
	odph_thread_param_init(&thr_param);
	thr_param.start = run_worker;
	thr_param.thr_type = ODP_THREAD_WORKER;
	thr_param.arg = worker_config;
	odp_atomic_store_u32(&worker_config->is_running, 1U);
	/* Control thread + worker thread = barrier count */
	odp_barrier_init(&worker_config->barrier, 2);

	if (odph_thread_create(&worker_config->thread, &thr_common, &thr_param, 1) != 1) {
		log_fn(ODP_LOG_ERR, "Error creating worker\n");
		(void)odp_queue_destroy(worker_config->queue);
		(void)odp_schedule_group_destroy(worker_config->grp);
		return false;
	}

	odp_barrier_wait(&worker_config->barrier);
	++config->num_workers;

	if (config->num_workers == 1U && !bootstrap_scheduling(worker_config, config->pool))
		return false;

	return true;
}

static odp_bool_t remove_worker(prog_config_t *config, uint8_t idx)
{
	worker_config_t *worker_config;

	if (config->num_workers == 0U) {
		log_fn(ODP_LOG_WARN, "No more workers to remove\n");
		return false;
	}

	if (idx >= MAX_WORKERS) {
		log_fn(ODP_LOG_ERR, "Worker index out of bounds: %u\n", idx);
		return false;
	}

	worker_config = &config->worker_config[idx];

	if (worker_config->thread.cpu == -1) {
		log_fn(ODP_LOG_WARN, "Worker already removed: %u\n", idx);
		return false;
	}

	shutdown_worker(worker_config);
	--config->num_workers;
	worker_config->thread.cpu = -1;
	config->pending_summary = &worker_config->summary;

	return true;
}

static odp_bool_t do_exit(prog_config_t *config, uint8_t aux ODP_UNUSED)
{
	for (uint32_t i = 0U; i < MAX_WORKERS; ++i)
		remove_worker(config, i);

	return true;
}

static void run_prog(prog_config_t *config)
{
	odp_bool_t is_running = true;
	int socket = config->socket;
	ssize_t ret;
	uint8_t data, cmd, aux;

	while (is_running) {
		ret = TEMP_FAILURE_RETRY(recv(socket, &data, sizeof(data), 0));

		if (ret != 1)
			continue;

		decode_cmd(data, &cmd, &aux);

		switch (cmd) {
		case ADD_WORKER:
			run_command(add_worker, aux, config, socket);
			break;
		case REM_WORKER:
			run_command(remove_worker, aux, config, socket);
			break;
		case EXIT_PROG:
			run_command(do_exit, aux, config, socket);
			is_running = false;
			break;
		default:
			break;
		}
	}
}

static void teardown_prog(prog_config_t *config)
{
	(void)odp_pool_destroy(config->pool);
}

static void run_odp(char *cpumask, int socket)
{
	odp_instance_t odp_instance;
	odp_init_t param;
	odp_shm_t shm_cfg = ODP_SHM_INVALID;

	odp_init_param_init(&param);
	param.log_fn = log_fn;

	if (odp_init_global(&odp_instance, &param, NULL)) {
		log_fn(ODP_LOG_ERR, "ODP global init failed\n");
		return;
	}

	if (odp_init_local(odp_instance, ODP_THREAD_CONTROL)) {
		log_fn(ODP_LOG_ERR, "ODP local init failed\n");
		return;
	}

	shm_cfg = odp_shm_reserve(NULL, sizeof(prog_config_t), ODP_CACHE_LINE_SIZE, 0U);

	if (shm_cfg == ODP_SHM_INVALID) {
		log_fn(ODP_LOG_ERR, "Error reserving shared memory\n");
		return;
	}

	prog_conf = odp_shm_addr(shm_cfg);

	if (prog_conf == NULL) {
		log_fn(ODP_LOG_ERR, "Error resolving shared memory address\n");
		return;
	}

	if (odp_schedule_config(NULL) < 0) {
		log_fn(ODP_LOG_ERR, "Error configuring scheduler\n");
		return;
	}

	if (!setup_prog_config(prog_conf, odp_instance, cpumask, socket))
		return;

	if (!signal_ready(prog_conf->socket))
		return;

	run_prog(prog_conf);
	teardown_prog(prog_conf);
	(void)odp_shm_free(shm_cfg);

	if (odp_term_local()) {
		log_fn(ODP_LOG_ERR, "ODP local terminate failed\n");
		return;
	}

	if (odp_term_global(odp_instance)) {
		log_fn(ODP_LOG_ERR, "ODP global terminate failed\n");
		return;
	}
}

static odp_bool_t wait_process_ready(int socket)
{
	uint8_t data;
	ssize_t ret;

	ret = TEMP_FAILURE_RETRY(recv(socket, &data, sizeof(data), 0));

	if (ret <= 0) {
		if (ret < 0)
			perror("recv");

		return false;
	}

	return true;
}

static inline odp_bool_t is_interactive(const global_config_t *config)
{
	return config->num_p_elems == 0U;
}

static void print_cli_usage(void)
{
	printf("\nValid commands are:\n\n");

	for (uint32_t i = 0U; i < ODPH_ARRAY_SIZE(cmdstrs); ++i)
		printf("    %s <process index> <worker index>\n", cmdstrs[i]);

	printf("\n");
}

static char *get_format_str(uint32_t max_cmd_len)
{
	const int cmd_len = snprintf(NULL, 0U, "%u", max_cmd_len);
	uint32_t str_len;

	if (cmd_len <= 0)
		return NULL;

	str_len = strlen("%s %u %u") + cmd_len + 1U;

	char fmt[str_len];

	snprintf(fmt, str_len, "%%%ds %%u %%u", max_cmd_len);

	return strdup(fmt);
}

static uint8_t map_str_to_command(const char *cmdstr, uint32_t len)
{
	for (uint32_t i = 0U; i < ODPH_ARRAY_SIZE(cmdstrs); ++i)
		if (strncmp(cmdstr, cmdstrs[i], len) == 0)
			return i;

	return UNKNOWN_CMD;
}

static odp_bool_t get_stdin_command(global_config_t *config, uint8_t *cmd, uint32_t *prog_idx,
				    uint32_t *worker_idx)
{
	char *input, cmdstr[config->max_cmd_len + 1U], *fmt;
	size_t size;
	ssize_t ret;

	input = NULL;
	memset(cmdstr, 0, sizeof(cmdstr));
	printf("> ");
	ret = getline(&input, &size, stdin);

	if (ret == -1)
		return false;

	fmt = get_format_str(config->max_cmd_len);

	if (fmt == NULL) {
		printf("Unable to parse command\n");
		return false;
	}

	ret = sscanf(input, fmt, cmdstr, prog_idx, worker_idx);
	free(input);
	free(fmt);

	if (ret == EOF)
		return false;

	if (ret != 3) {
		printf("Unable to parse command\n");
		return false;
	}

	*cmd = map_str_to_command(cmdstr, config->max_cmd_len);
	return true;
}

static uint8_t map_char_to_command(char cmdchar)
{
	switch (cmdchar) {
	case ADDITION:
		return ADD_WORKER;
	case REMOVAL:
		return REM_WORKER;
	case DELAY:
		return DELAY_PROG;
	default:
		return UNKNOWN_CMD;
	}
}

static odp_bool_t get_pattern_command(global_config_t *config, uint8_t *cmd, uint32_t *prog_idx,
				      uint32_t *worker_idx)
{
	static uint32_t i;
	const pattern_t *pattern;
	struct timespec ts;

	if (i == config->num_p_elems) {
		config->is_running = false;
		return false;
	}

	pattern = &config->pattern[i++];
	*cmd = map_char_to_command(pattern->op);

	if (*cmd == DELAY_PROG) {
		ts.tv_sec  = pattern->val1 / ODP_TIME_SEC_IN_NS;
		ts.tv_nsec = pattern->val1 % ODP_TIME_SEC_IN_NS;
		nanosleep(&ts, NULL);
		return false;
	}

	*prog_idx = pattern->val1;
	*worker_idx = pattern->val2;

	return true;
}

static inline uint8_t encode_cmd(uint8_t cmd, uint8_t worker_idx)
{
	/* Actual command will be in the high nibble and worker index in the low nibble. */
	cmd <<= 4U;
	cmd |= worker_idx;

	return cmd;
}

static odp_bool_t is_peer_down(int error)
{
	return error == ECONNRESET || error == EPIPE || error == ETIMEDOUT;
}

static int send_command(int socket, uint8_t cmd)
{
	uint8_t data;
	ssize_t ret;
	odp_bool_t is_down;

	ret = TEMP_FAILURE_RETRY(send(socket, &cmd, sizeof(cmd), MSG_NOSIGNAL));

	if (ret != 1) {
		is_down = is_peer_down(errno);
		perror("send");
		return is_down ? PEER_ERR : CONN_ERR;
	}

	ret = TEMP_FAILURE_RETRY(recv(socket, &data, sizeof(data), 0));

	if (ret <= 0) {
		is_down = ret == 0 || is_peer_down(errno);

		if (ret < 0)
			perror("recv");

		return is_down ? PEER_ERR : CONN_ERR;
	}

	return data;
}

static odp_bool_t recv_summary(int socket, summary_t *summary)
{
	const ssize_t size = sizeof(*summary),
	ret = TEMP_FAILURE_RETRY(recv(socket, summary, size, 0));

	return ret == size;
}

static void dump_summary(pid_t pid, const summary_t *summary)
{
	printf("\nremoved worker summary:\n"
	       "    ODP process ID: %d\n"
	       "    thread ID:      %" PRIu64 "\n"
	       "    events handled: %" PRIu64 "\n"
	       "    enqueue errors: %" PRIu64 "\n"
	       "    runtime:        %" PRIu64 " (ns)\n\n", pid, summary->thread_id,
	       summary->num_handled, summary->enq_errs, summary->runtime);
}

static odp_bool_t check_summary(const summary_t *summary)
{
	if (summary->num_handled == 0U) {
		printf("Summary check failure: no events handled\n");
		return false;
	}

	if (summary->enq_errs > 0U) {
		printf("Summary check failure: enqueue errors\n");
		return false;
	}

	if (summary->runtime == 0U) {
		printf("Summary check failure: no run time recorded\n");
		return false;
	}

	return true;
}

static void dump_result(int socket, pid_t pid)
{
	result_t result;
	const ssize_t size = sizeof(result),
	ret = TEMP_FAILURE_RETRY(recv(socket, &result, size, 0));

	if (ret != size)
		return;

	printf("\nODP process %d:\n"
	       "|\n", pid);

	for (uint32_t i = 0U; i < MAX_WORKERS; i++)
		if (result.workers[i].is_active)
			printf("|--- Worker thread ID %u on CPU %u\n",
			       result.workers[i].thread_id, result.workers[i].cpu);

	printf("\n");
}

static odp_bool_t run_global(global_config_t *config)
{
	input_fn_t input_fn;
	uint32_t prog_idx, worker_idx;
	uint8_t cmd;
	prog_t *prog;
	ssize_t ret;
	odp_bool_t is_recv, func_ret = true;

	print_cli_usage();
	input_fn = is_interactive(config) ? get_stdin_command : get_pattern_command;
	config->is_running = true;

	while (config->is_running) {
		if (!input_fn(config, &cmd, &prog_idx, &worker_idx))
			continue;

		if (cmd == UNKNOWN_CMD) {
			printf("Unrecognized command\n");
			continue;
		}

		if (prog_idx >= config->num_progs) {
			printf("Invalid process index: %u\n", prog_idx);
			continue;
		}

		prog = &config->progs[prog_idx];

		if (prog->state == DOWN) {
			printf("ODP process index %u has already exited\n", prog_idx);
			continue;
		}

		ret = send_command(prog->socket, encode_cmd(cmd, worker_idx));

		if (ret == CONN_ERR) {
			printf("Fatal connection error, aborting\n");
			abort();
		}

		if (ret == PEER_ERR) {
			printf("ODP process index %u has exited\n", prog_idx);
			prog->state = DOWN;
			continue;
		}

		if (ret == CMD_NOK) {
			printf("ODP process index %u was unable to execute the command\n",
			       prog_idx);
			continue;
		}

		if (ret == CMD_SUMMARY) {
			is_recv = recv_summary(prog->socket, &prog->summary);

			if (is_recv)
				dump_summary(prog->pid, &prog->summary);

			if (!is_interactive(config) &&
			    !(is_recv && check_summary(&prog->summary))) {
				config->is_running = false;
				func_ret = false;
			}

			continue;
		}

		if (ret == CMD_OK)
			dump_result(prog->socket, prog->pid);
	}

	for (uint32_t i = 0U; i < config->num_progs; ++i) {
		prog = &config->progs[i];

		if (prog->state == UP) {
			for (uint32_t j = 0U; j < MAX_WORKERS; ++j) {
				ret = send_command(prog->socket, encode_cmd(REM_WORKER, j));

				if (ret == CONN_ERR || ret == PEER_ERR)
					break;

				if (ret != CMD_SUMMARY)
					continue;

				if (recv_summary(prog->socket, &prog->summary))
					dump_summary(prog->pid, &prog->summary);
			}

			(void)send_command(prog->socket, encode_cmd(EXIT_PROG, 0));
			(void)TEMP_FAILURE_RETRY(waitpid(prog->pid, NULL, 0));
		}
	}

	return func_ret;
}

static void teardown_global(const global_config_t *config)
{
	const prog_t *prog;

	for (uint32_t i = 0U; i < config->num_progs; ++i) {
		prog = &config->progs[i];
		close(prog->socket);
	}
}

int main(int argc, char **argv)
{
	parse_result_t res;
	int ret, func_ret = EXIT_SUCCESS;
	prog_t *prog;
	pid_t pid, ppid;
	const size_t envsize = strlen(ENV_PREFIX S(MAX_PROGS)) + 1U;
	char *env, prog_env[envsize];

	if (!setup_signals()) {
		printf("Error setting up signals, exiting\n");
		return EXIT_FAILURE;
	}

	res = parse_options(argc, argv, &conf);

	if (res == PRS_NOK)
		return EXIT_FAILURE;

	if (res == PRS_TERM)
		return EXIT_SUCCESS;

	printf("*** ODP dynamic worker tester ***\n\n");

	for (uint32_t i = 0U; i < conf.num_progs; ++i) {
		int sockets[2U];

		ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);

		if (ret == -1) {
			perror("socketpair");
			return EXIT_FAILURE;
		}

		prog = &conf.progs[i];
		snprintf(prog_env, envsize, "%s%u", ENV_PREFIX, i);
		env = getenv(prog_env);

		if (env != NULL)
			prog->env = strdup(env);

		prog->socket = sockets[PARENT];
		ppid = getpid();
		pid = fork();

		if (pid == -1) {
			perror("fork");
			return EXIT_FAILURE;
		}

		if (pid == 0) {
			close(sockets[PARENT]);

			if (!setup_pkill(ppid)) {
				log_fn(ODP_LOG_ERR, "Error setting up pdeath signal, exiting\n");
				return EXIT_FAILURE;
			}

			if (!disable_stream(STDIN_FILENO, true) ||
			    !disable_stream(STDERR_FILENO, false) ||
			    !disable_stream(STDOUT_FILENO, false)) {
				log_fn(ODP_LOG_ERR, "Error disabling streams, exiting\n");
				return EXIT_FAILURE;
			}

			if (prog->env != NULL && !set_odp_env(prog->env)) {
				log_fn(ODP_LOG_ERR, "Error setting up environment, exiting\n");
				return EXIT_FAILURE;
			}

			run_odp(prog->cpumask, sockets[CHILD]);
			goto exit;
		} else {
			close(sockets[CHILD]);
			prog->pid = pid;

			if (!wait_process_ready(prog->socket)) {
				printf("Error launching process: %d, exiting\n", prog->pid);
				return EXIT_FAILURE;
			}

			prog->state = UP;
			printf("Created ODP process, pid: %d, CPU mask: %s, process index: %u\n",
			       prog->pid, prog->cpumask, i);
		}
	}

	func_ret = run_global(&conf) ? EXIT_SUCCESS : EXIT_FAILURE;
	teardown_global(&conf);

exit:
	return func_ret;
}
