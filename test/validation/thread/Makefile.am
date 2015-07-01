include ../Makefile.inc

noinst_LIBRARIES = libthread.a
libthread_a_SOURCES = thread.c

bin_PROGRAMS = thread_main$(EXEEXT)
dist_thread_main_SOURCES = thread_main.c
thread_main_LDADD = libthread.a $(LIBCUNIT_COMMON) $(LIBODP)
