include ../Makefile.inc

noinst_LTLIBRARIES = libscheduler.la
libscheduler_la_SOURCES = scheduler.c

bin_PROGRAMS = scheduler_main$(EXEEXT)
dist_scheduler_main_SOURCES = scheduler_main.c
scheduler_main_LDADD = libscheduler.la $(LIBCUNIT_COMMON) $(LIBODP)
