include ../Makefile.inc

test_PROGRAMS = thread_main
thread_main_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_THRMASK
thread_main_SOURCES = thread.c
LDADD += $(LIBTHRMASK_COMMON)
