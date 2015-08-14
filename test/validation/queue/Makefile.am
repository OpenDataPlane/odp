include ../Makefile.inc

noinst_LTLIBRARIES = libqueue.la
libqueue_la_SOURCES = queue.c

bin_PROGRAMS = queue_main$(EXEEXT)
dist_queue_main_SOURCES = queue_main.c
queue_main_LDADD = libqueue.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = queue.h
