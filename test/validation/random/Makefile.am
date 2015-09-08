include ../Makefile.inc

noinst_LTLIBRARIES = librandom.la
librandom_la_SOURCES = random.c

bin_PROGRAMS = random_main$(EXEEXT)
dist_random_main_SOURCES = random_main.c
random_main_LDADD = librandom.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = random.h
