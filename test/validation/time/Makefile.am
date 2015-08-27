include ../Makefile.inc

noinst_LTLIBRARIES = libtime.la
libtime_la_SOURCES = time.c

bin_PROGRAMS = time_main$(EXEEXT)
dist_time_main_SOURCES = time_main.c
time_main_LDADD = libtime.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = time.h
