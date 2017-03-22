include ../Makefile.inc

# because most of driver activity occurs at init time, and due to the
# fact that many sequential ODP runs are not allowed from the same process,
# we need different binaries for each things being tested (as API init)

#tests for enumerator class registration:
noinst_LTLIBRARIES = libtestdrvdriverenumrclass.la
libtestdrvdriverenumrclass_la_SOURCES = drvdriver_enumr_class.c

test_PROGRAMS = drvdriver_enumr_class_main$(EXEEXT)
dist_drvdriver_enumr_class_main_SOURCES = drvdriver_enumr_class_main.c
drvdriver_enumr_class_main_LDADD = libtestdrvdriverenumrclass.la \
				   $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = drvdriver_enumr_class.h

#tests for enumerator registration:
noinst_LTLIBRARIES += libtestdrvdriverenumr.la
libtestdrvdriverenumr_la_SOURCES = drvdriver_enumr.c

test_PROGRAMS += drvdriver_enumr_main$(EXEEXT)
dist_drvdriver_enumr_main_SOURCES = drvdriver_enumr_main.c
drvdriver_enumr_main_LDADD = libtestdrvdriverenumr.la \
				   $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST += drvdriver_enumr.h
