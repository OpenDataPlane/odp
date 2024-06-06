include $(top_srcdir)/test/Makefile.inc

TESTS_ENVIRONMENT += TEST_DIR=${builddir}

EXECUTABLES = odp_atomic_perf \
	      odp_bench_buffer \
	      odp_bench_misc \
	      odp_bench_packet \
	      odp_bench_pktio_sp \
	      odp_bench_timer \
	      odp_crc \
	      odp_lock_perf \
	      odp_mem_perf \
	      odp_pktio_perf \
	      odp_pool_latency \
	      odp_pool_perf \
	      odp_queue_perf \
	      odp_stash_perf \
	      odp_random \
	      odp_stress

COMPILE_ONLY = odp_cpu_bench \
	       odp_crypto \
	       odp_dmafwd \
	       odp_dma_perf \
	       odp_ipsec \
	       odp_l2fwd \
	       odp_packet_gen \
	       odp_pktio_ordered \
	       odp_sched_latency \
	       odp_sched_perf \
	       odp_sched_pktio \
	       odp_timer_accuracy \
	       odp_timer_perf

if LIBCONFIG
COMPILE_ONLY += odp_ipsecfwd
endif

TESTSCRIPTS = odp_cpu_bench_run.sh \
	      odp_crypto_run.sh \
	      odp_dma_perf_run.sh \
	      odp_ipsec_run.sh \
	      odp_l2fwd_run.sh \
	      odp_packet_gen_run.sh \
	      odp_sched_latency_run.sh \
	      odp_sched_perf_run.sh \
	      odp_sched_pktio_run.sh \
	      odp_timer_accuracy_run.sh \
	      odp_timer_perf_run.sh

if ODP_PKTIO_PCAP
TESTSCRIPTS += odp_dmafwd_run.sh \
	       odp_pktio_ordered_run.sh
endif

TEST_EXTENSIONS = .sh

if test_perf
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

odp_atomic_perf_SOURCES = odp_atomic_perf.c
odp_bench_buffer_SOURCES = odp_bench_buffer.c
odp_bench_misc_SOURCES = odp_bench_misc.c
odp_bench_packet_SOURCES = odp_bench_packet.c
odp_bench_pktio_sp_SOURCES = odp_bench_pktio_sp.c
odp_bench_timer_SOURCES = odp_bench_timer.c
odp_cpu_bench_SOURCES = odp_cpu_bench.c
odp_crc_SOURCES = odp_crc.c
odp_crypto_SOURCES = odp_crypto.c
odp_dmafwd_SOURCES = odp_dmafwd.c
odp_dma_perf_SOURCES = odp_dma_perf.c
odp_ipsec_SOURCES = odp_ipsec.c
odp_lock_perf_SOURCES = odp_lock_perf.c
odp_mem_perf_SOURCES = odp_mem_perf.c
odp_packet_gen_SOURCES = odp_packet_gen.c
odp_pktio_ordered_SOURCES = odp_pktio_ordered.c dummy_crc.h
odp_sched_latency_SOURCES = odp_sched_latency.c
odp_sched_pktio_SOURCES = odp_sched_pktio.c
odp_pktio_perf_SOURCES = odp_pktio_perf.c
odp_pool_latency_SOURCES = odp_pool_latency.c
odp_pool_perf_SOURCES = odp_pool_perf.c
odp_queue_perf_SOURCES = odp_queue_perf.c
odp_random_SOURCES = odp_random.c
odp_sched_perf_SOURCES = odp_sched_perf.c
odp_stress_SOURCES = odp_stress.c
odp_timer_accuracy_SOURCES = odp_timer_accuracy.c
odp_timer_perf_SOURCES = odp_timer_perf.c

if LIBCONFIG
odp_ipsecfwd_SOURCES = odp_ipsecfwd.c
AM_CFLAGS += $(LIBCONFIG_CFLAGS)
endif

PRELDADD += $(LIBBENCH_COMMON) $(LIBTEST_COMMON)

dist_check_SCRIPTS = $(TESTSCRIPTS)

dist_check_DATA = udp64.pcap

# If building out-of-tree, make check will not copy the scripts and data to the
# $(builddir) assuming that all commands are run locally. However this prevents
# running tests on a remote target using LOG_COMPILER.
# So copy all script and data files explicitly here.
all-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(dist_check_SCRIPTS) $(dist_check_DATA); do \
			if [ -e $(srcdir)/$$f ]; then \
				mkdir -p $(builddir)/$$(dirname $$f); \
				cp -f $(srcdir)/$$f $(builddir)/$$f; \
			fi \
		done \
	fi
clean-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(dist_check_SCRIPTS) $(dist_check_DATA); do \
			rm -f $(builddir)/$$f; \
		done \
	fi
