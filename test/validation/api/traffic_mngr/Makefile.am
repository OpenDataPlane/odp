include ../Makefile.inc

TESTS_ENVIRONMENT += TEST_DIR=${builddir}

TESTSCRIPTS = traffic_mngr.sh
TEST_EXTENSIONS = .sh

TESTS = $(TESTSCRIPTS)

test_PROGRAMS = traffic_mngr_main
traffic_mngr_main_SOURCES = traffic_mngr.c
LDADD += -lm

dist_check_SCRIPTS = $(TESTSCRIPTS)
test_SCRIPTS = $(dist_check_SCRIPTS)
