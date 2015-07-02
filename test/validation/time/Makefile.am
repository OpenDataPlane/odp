include ../Makefile.inc

noinst_LIBRARIES = libtime.a
libtime_a_SOURCES = time.c

bin_PROGRAMS = time_main$(EXEEXT)
dist_time_main_SOURCES = time_main.c
time_main_LDADD = libtime.a $(LIBCUNIT_COMMON) $(LIBODP)
