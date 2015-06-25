include ../Makefile.inc

noinst_LIBRARIES = libpool.a
libpool_a_SOURCES = pool.c

bin_PROGRAMS = pool_main$(EXEEXT)
dist_pool_main_SOURCES = pool_main.c
pool_main_LDADD = libpool.a $(LIBCUNIT_COMMON) $(LIBODP)
