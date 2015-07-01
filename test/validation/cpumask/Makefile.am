include ../Makefile.inc

noinst_LIBRARIES = libcpumask.a
libcpumask_a_SOURCES = cpumask.c

bin_PROGRAMS = cpumask_main$(EXEEXT)
dist_cpumask_main_SOURCES = cpumask_main.c
cpumask_main_LDADD = libcpumask.a $(LIBCUNIT_COMMON) $(LIBODP)
