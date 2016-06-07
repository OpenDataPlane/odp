include ../Makefile.inc

noinst_LTLIBRARIES = libtestring.la
libtestring_la_SOURCES = ring_suites.c ring_basic.c ring_stress.c
libtestring_la_CFLAGS = $(AM_CFLAGS) $(INCCUNIT_COMMON) $(INCODP)

test_PROGRAMS = ring_main$(EXEEXT)
dist_ring_main_SOURCES = ring_main.c

ring_main_LDFLAGS = $(AM_LDFLAGS)
ring_main_LDADD = libtestring.la $(LIBCUNIT_COMMON) $(LIBODP)

noinst_HEADERS = ring_suites.h

