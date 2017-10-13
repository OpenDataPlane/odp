include ../Makefile.inc

test_PROGRAMS = thread_main$(EXEEXT)
thread_main_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_THRMASK
thread_main_SOURCES = thread_main.c thread.c thread.h
thread_main_LDADD = $(LIBTHRMASK_COMMON) $(LIBCUNIT_COMMON) $(LIBODP)
