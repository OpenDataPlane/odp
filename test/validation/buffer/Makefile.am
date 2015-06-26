include ../Makefile.inc

noinst_LIBRARIES = libbuffer.a
libbuffer_a_SOURCES = buffer.c

bin_PROGRAMS = buffer_main$(EXEEXT)
dist_buffer_main_SOURCES = buffer_main.c
buffer_main_LDADD = libbuffer.a $(LIBCUNIT_COMMON) $(LIBODP)
