include ../Makefile.inc

noinst_LTLIBRARIES = libsynchronizers.la
libsynchronizers_la_SOURCES = synchronizers.c

bin_PROGRAMS = synchronizers_main$(EXEEXT)
dist_synchronizers_main_SOURCES = synchronizers_main.c
synchronizers_main_LDADD = libsynchronizers.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = synchronizers.h
