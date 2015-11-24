include ../Makefile.inc

noinst_LTLIBRARIES = libtestsynchronizers.la
libtestsynchronizers_la_SOURCES = synchronizers.c

test_PROGRAMS = synchronizers_main$(EXEEXT)
dist_synchronizers_main_SOURCES = synchronizers_main.c
synchronizers_main_LDADD = libtestsynchronizers.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = synchronizers.h
