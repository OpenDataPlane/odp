include ../Makefile.inc

noinst_LTLIBRARIES = libcpumask.la
libcpumask_la_SOURCES = cpumask.c

bin_PROGRAMS = cpumask_main$(EXEEXT)
dist_cpumask_main_SOURCES = cpumask_main.c
cpumask_main_LDADD = libcpumask.la $(LIBCUNIT_COMMON) $(LIBODP)
