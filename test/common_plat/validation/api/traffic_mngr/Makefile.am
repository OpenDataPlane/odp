include ../Makefile.inc

TESTS_ENVIRONMENT += TEST_DIR=${builddir}

TESTSCRIPTS = traffic_mngr.sh
TEST_EXTENSIONS = .sh

TESTS = $(TESTSCRIPTS)

noinst_LTLIBRARIES = libtesttraffic_mngr.la
libtesttraffic_mngr_la_SOURCES = traffic_mngr.c

bin_PROGRAMS = traffic_mngr_main$(EXEEXT)
dist_traffic_mngr_main_SOURCES = traffic_mngr_main.c
traffic_mngr_main_LDADD = libtesttraffic_mngr.la -lm $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = traffic_mngr.h $(TESTSCRIPTS)
dist_check_SCRIPTS = $(TESTSCRIPTS)
