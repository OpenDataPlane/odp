include ../Makefile.inc

noinst_LTLIBRARIES = libshmem.la
libshmem_la_SOURCES = shmem.c

bin_PROGRAMS = shmem_main$(EXEEXT)
dist_shmem_main_SOURCES = shmem_main.c
shmem_main_LDADD = libshmem.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = shmem.h
