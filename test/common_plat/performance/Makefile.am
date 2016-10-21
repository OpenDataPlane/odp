include $(top_srcdir)/test/Makefile.inc

TESTS_ENVIRONMENT += TEST_DIR=${builddir}

EXECUTABLES = odp_crypto$(EXEEXT) odp_pktio_perf$(EXEEXT)

COMPILE_ONLY = odp_l2fwd$(EXEEXT) \
	       odp_sched_latency$(EXEEXT) \
	       odp_scheduling$(EXEEXT)

TESTSCRIPTS = odp_l2fwd_run.sh \
	      odp_sched_latency_run.sh \
	      odp_scheduling_run.sh

TEST_EXTENSIONS = .sh

if test_perf
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

odp_crypto_LDFLAGS = $(AM_LDFLAGS) -static
odp_crypto_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/test
odp_sched_latency_LDFLAGS = $(AM_LDFLAGS) -static
odp_sched_latency_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/test
odp_scheduling_LDFLAGS = $(AM_LDFLAGS) -static
odp_scheduling_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/test

noinst_HEADERS = \
		  $(top_srcdir)/test/test_debug.h

dist_odp_crypto_SOURCES = odp_crypto.c
dist_odp_sched_latency_SOURCES = odp_sched_latency.c
dist_odp_scheduling_SOURCES = odp_scheduling.c
dist_odp_pktio_perf_SOURCES = odp_pktio_perf.c

EXTRA_DIST = $(TESTSCRIPTS)
