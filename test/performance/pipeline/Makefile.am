include $(top_srcdir)/test/Makefile.inc

if LIBCONFIG
AM_CFLAGS += \
	$(LIBCONFIG_CFLAGS) \
	-I$(top_srcdir)/test/performance/pipeline

bin_PROGRAMS = odp_pipeline

odp_pipeline_SOURCES = \
	cls_parser.c \
	common.h \
	config_parser.h \
	config_parser.c \
	cpumap.h \
	cpumap_parser.c \
	crypto_parser.c \
	dma_parser.c \
	flow.h \
	flow.c \
	flow_parser.c \
	helpers.h \
	main.c \
	orchestrator.h \
	orchestrator.c \
	pktio_parser.c \
	pool_parser.c \
	queue_parser.c \
	sched_parser.c \
	stash_parser.c \
	timer_parser.c \
	work.h \
	work.c \
	work_forward.c \
	work_global_forward.c \
	work_packet_copy.c \
	work_packet_source.c \
	work_sink.c \
	work_timeout_source.c \
	work_wait.c \
	worker.h \
	worker_parser.c
endif
