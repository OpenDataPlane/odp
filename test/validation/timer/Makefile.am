include ../Makefile.inc

noinst_LTLIBRARIES = libtimer.la
libtimer_la_SOURCES = timer.c

bin_PROGRAMS = timer_main$(EXEEXT)
dist_timer_main_SOURCES = timer_main.c
timer_main_LDADD = libtimer.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = timer.h
