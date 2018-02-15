include ../Makefile.inc

TESTS_ENVIRONMENT += TEST_DIR=${builddir}

test_PROGRAMS = traffic_mngr_main
traffic_mngr_main_SOURCES = traffic_mngr.c
LDADD += -lm

dist_check_SCRIPTS = traffic_mngr.sh
test_SCRIPTS = $(dist_check_SCRIPTS)
