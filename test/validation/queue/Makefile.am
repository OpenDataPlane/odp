include ../Makefile.inc

noinst_LIBRARIES = libqueue.a
libqueue_a_SOURCES = queue.c

bin_PROGRAMS = queue_main$(EXEEXT)
dist_queue_main_SOURCES = queue_main.c
queue_main_LDADD = libqueue.a $(LIBCUNIT_COMMON) $(LIBODP)
