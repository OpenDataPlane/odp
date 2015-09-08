include ../Makefile.inc

noinst_LTLIBRARIES = libpool.la
libpool_la_SOURCES = pool.c

bin_PROGRAMS = pool_main$(EXEEXT)
dist_pool_main_SOURCES = pool_main.c
pool_main_LDADD = libpool.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = pool.h
