include ../Makefile.inc

noinst_LTLIBRARIES = libbuffer.la
libbuffer_la_SOURCES = buffer.c

bin_PROGRAMS = buffer_main$(EXEEXT)
dist_buffer_main_SOURCES = buffer_main.c
buffer_main_LDADD = libbuffer.la $(LIBCUNIT_COMMON) $(LIBODP)
