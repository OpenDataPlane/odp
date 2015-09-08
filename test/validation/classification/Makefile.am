include ../Makefile.inc

noinst_LTLIBRARIES = libclassification.la
libclassification_la_SOURCES = odp_classification_basic.c \
			       odp_classification_tests.c \
			       classification.c

bin_PROGRAMS = classification_main$(EXEEXT)
dist_classification_main_SOURCES = classification_main.c
classification_main_LDADD = libclassification.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = classification.h odp_classification_testsuites.h
