include ../Makefile.inc

test_PROGRAMS = thread_main
thread_main_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_THRMASK
thread_main_SOURCES = thread_main.c thread.c thread.h
LDADD += $(LIBTHRMASK_COMMON)
