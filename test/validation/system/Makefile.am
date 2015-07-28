include ../Makefile.inc

noinst_LTLIBRARIES = libsystem.la
libsystem_la_SOURCES = system.c

bin_PROGRAMS = system_main$(EXEEXT)
dist_system_main_SOURCES = system_main.c
system_main_LDADD = libsystem.la $(LIBCUNIT_COMMON) $(LIBODP)
