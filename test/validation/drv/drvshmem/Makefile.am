include ../Makefile.inc

noinst_LTLIBRARIES = libtestdrvshmem.la
libtestdrvshmem_la_SOURCES = drvshmem.c

test_PROGRAMS = drvshmem_main$(EXEEXT)
dist_drvshmem_main_SOURCES = drvshmem_main.c
drvshmem_main_LDADD = libtestdrvshmem.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = drvshmem.h
