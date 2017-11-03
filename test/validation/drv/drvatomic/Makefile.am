include ../Makefile.inc

noinst_LTLIBRARIES = libtestdrvatomic.la
libtestdrvatomic_la_SOURCES = drvatomic.c

test_PROGRAMS = drvatomic_main$(EXEEXT)
dist_drvatomic_main_SOURCES = drvatomic_main.c
drvatomic_main_LDADD = libtestdrvatomic.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = drvatomic.h
