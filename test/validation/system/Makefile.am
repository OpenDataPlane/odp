include ../Makefile.inc

noinst_LIBRARIES = libsystem.a
libsystem_a_SOURCES = system.c

bin_PROGRAMS = system_main$(EXEEXT)
dist_system_main_SOURCES = system_main.c
system_main_LDADD = libsystem.a $(LIBCUNIT_COMMON) $(LIBODP)
