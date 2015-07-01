include ../Makefile.inc

noinst_LIBRARIES = libsynchronizers.a
libsynchronizers_a_SOURCES = synchronizers.c

bin_PROGRAMS = synchronizers_main$(EXEEXT)
dist_synchronizers_main_SOURCES = synchronizers_main.c
synchronizers_main_LDADD = libsynchronizers.a $(LIBCUNIT_COMMON) $(LIBODP)
