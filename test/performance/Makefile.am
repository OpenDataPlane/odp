include $(top_srcdir)/test/Makefile.inc

TESTS_ENVIRONMENT += TEST_DIR=${builddir}

EXECUTABLES = odp_bench_packet \
	      odp_cpu_bench \
	      odp_crypto \
	      odp_ipsec \
	      odp_pktio_perf \
	      odp_pool_perf \
	      odp_queue_perf \
	      odp_sched_perf \
	      odp_timer_perf

COMPILE_ONLY = odp_l2fwd \
	       odp_pktio_ordered \
	       odp_sched_latency \
	       odp_sched_pktio \
	       odp_scheduling

TESTSCRIPTS = odp_l2fwd_run.sh \
	      odp_sched_latency_run.sh \
	      odp_sched_pktio_run.sh \
	      odp_scheduling_run.sh

if HAVE_PCAP
TESTSCRIPTS += odp_pktio_ordered_run.sh
endif

TEST_EXTENSIONS = .sh

if test_perf
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

odp_bench_packet_SOURCES = odp_bench_packet.c
odp_cpu_bench_SOURCES = odp_cpu_bench.c
odp_crypto_SOURCES = odp_crypto.c
odp_ipsec_SOURCES = odp_ipsec.c
odp_pktio_ordered_SOURCES = odp_pktio_ordered.c dummy_crc.h
odp_sched_latency_SOURCES = odp_sched_latency.c
odp_sched_pktio_SOURCES = odp_sched_pktio.c
odp_scheduling_SOURCES = odp_scheduling.c
odp_pktio_perf_SOURCES = odp_pktio_perf.c
odp_pool_perf_SOURCES = odp_pool_perf.c
odp_queue_perf_SOURCES = odp_queue_perf.c
odp_sched_perf_SOURCES = odp_sched_perf.c
odp_timer_perf_SOURCES = odp_timer_perf.c

# l2fwd test depends on generator example
EXTRA_odp_l2fwd_DEPENDENCIES = example-generator
.PHONY: $(EXTRA_odp_l2fwd_DEPENDENCIES)
example-generator:
	$(MAKE) -C $(top_builddir)/example/generator odp_generator$(EXEEXT)

dist_check_SCRIPTS = $(TESTSCRIPTS)

dist_check_DATA = udp64.pcap
