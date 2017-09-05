include $(top_srcdir)/test/Makefile.inc

TESTS_ENVIRONMENT += TEST_DIR=${builddir}

EXECUTABLES = odp_bench_packet$(EXEEXT) \
			  odp_crypto$(EXEEXT) \
			  odp_pktio_perf$(EXEEXT)

COMPILE_ONLY = odp_l2fwd$(EXEEXT) \
	       odp_pktio_ordered$(EXEEXT) \
	       odp_sched_latency$(EXEEXT) \
	       odp_scheduling$(EXEEXT)

TESTSCRIPTS = odp_l2fwd_run.sh \
	      odp_pktio_ordered_run.sh \
	      odp_sched_latency_run.sh \
	      odp_scheduling_run.sh

TEST_EXTENSIONS = .sh

if test_perf
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

noinst_HEADERS = \
		  $(top_srcdir)/test/test_debug.h

odp_bench_packet_SOURCES = odp_bench_packet.c
odp_crypto_SOURCES = odp_crypto.c
odp_pktio_ordered_SOURCES = odp_pktio_ordered.c dummy_crc.h
odp_sched_latency_SOURCES = odp_sched_latency.c
odp_scheduling_SOURCES = odp_scheduling.c
odp_pktio_perf_SOURCES = odp_pktio_perf.c

dist_check_SCRIPTS = $(TESTSCRIPTS)

dist_check_DATA = udp64.pcap
