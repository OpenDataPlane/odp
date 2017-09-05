include ../Makefile.inc

test_PROGRAMS = classification_main$(EXEEXT)
classification_main_SOURCES = classification_main.c \
				   odp_classification_basic.c \
				   odp_classification_tests.c \
				   odp_classification_testsuites.h \
				   odp_classification_test_pmr.c \
				   odp_classification_common.c \
				   classification.c \
				   classification.h
classification_main_LDADD = $(LIBCUNIT_COMMON) $(LIBODP)
