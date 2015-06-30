include ../Makefile.inc

noinst_LIBRARIES = libscheduler.a
libscheduler_a_SOURCES = scheduler.c

bin_PROGRAMS = scheduler_main$(EXEEXT)
dist_scheduler_main_SOURCES = scheduler_main.c
scheduler_main_LDADD = libscheduler.a $(LIBCUNIT_COMMON) $(LIBODP)
