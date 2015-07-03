include ../Makefile.inc

noinst_LIBRARIES = libclassification.a
libclassification_a_SOURCES = odp_classification_basic.c \
			      odp_classification_tests.c \
			      classification.c

bin_PROGRAMS = classification_main$(EXEEXT)
dist_classification_main_SOURCES = classification_main.c
classification_main_LDADD = libclassification.a $(LIBCUNIT_COMMON) $(LIBODP)
