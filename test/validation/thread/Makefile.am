include ../Makefile.inc

noinst_LTLIBRARIES = libthread.la
libthread_la_SOURCES = thread.c

bin_PROGRAMS = thread_main$(EXEEXT)
dist_thread_main_SOURCES = thread_main.c
thread_main_LDADD = libthread.la $(LIBCUNIT_COMMON) $(LIBODP)
