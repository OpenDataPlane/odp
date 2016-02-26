include ../Makefile.inc

noinst_LTLIBRARIES = libtesttraffic_mngr.la
libtesttraffic_mngr_la_SOURCES = traffic_mngr.c

test_PROGRAMS = traffic_mngr_main$(EXEEXT)
dist_traffic_mngr_main_SOURCES = traffic_mngr_main.c
traffic_mngr_main_LDADD = libtesttraffic_mngr.la -lm $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = traffic_mngr.h
