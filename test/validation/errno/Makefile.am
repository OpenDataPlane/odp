include ../Makefile.inc

noinst_LIBRARIES = liberrno.a
liberrno_a_SOURCES = errno.c

bin_PROGRAMS = errno_main$(EXEEXT)
dist_errno_main_SOURCES = errno_main.c
errno_main_LDADD = liberrno.a $(LIBCUNIT_COMMON) $(LIBODP)
