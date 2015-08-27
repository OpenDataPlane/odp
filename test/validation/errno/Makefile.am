include ../Makefile.inc

noinst_LTLIBRARIES = liberrno.la
liberrno_la_SOURCES = errno.c

bin_PROGRAMS = errno_main$(EXEEXT)
dist_errno_main_SOURCES = errno_main.c
errno_main_LDADD = liberrno.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = errno.h
