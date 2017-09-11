include $(top_srcdir)/test/Makefile.inc

TESTS_ENVIRONMENT += TEST_DIR=${builddir}

TESTSCRIPTS = odp_scheduling_run_proc.sh

TEST_EXTENSIONS = .sh

if test_perf_proc
TESTS = $(TESTSCRIPTS)
endif

dist_check_SCRIPTS = $(TESTSCRIPTS)
