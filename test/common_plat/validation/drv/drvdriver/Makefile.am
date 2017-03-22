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

#tests for device creation:
noinst_LTLIBRARIES += libtestdrvdriverdevice.la
libtestdrvdriverdevice_la_SOURCES = drvdriver_device.c

test_PROGRAMS += drvdriver_device_main$(EXEEXT)
dist_drvdriver_device_main_SOURCES = drvdriver_device_main.c
drvdriver_device_main_LDADD = libtestdrvdriverdevice.la \
				   $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST += drvdriver_device.h

#tests for devio creation:
noinst_LTLIBRARIES += libtestdrvdriverdevio.la
libtestdrvdriverdevio_la_SOURCES = drvdriver_devio.c

test_PROGRAMS += drvdriver_devio_main$(EXEEXT)
dist_drvdriver_devio_main_SOURCES = drvdriver_devio_main.c
drvdriver_devio_main_LDADD = libtestdrvdriverdevio.la \
				   $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST += drvdriver_devio.h

#tests for driver registration and probing:
noinst_LTLIBRARIES += libtestdrvdriverdriver.la
libtestdrvdriverdriver_la_SOURCES = drvdriver_driver.c

test_PROGRAMS += drvdriver_driver_main$(EXEEXT)
dist_drvdriver_driver_main_SOURCES = drvdriver_driver_main.c
drvdriver_driver_main_LDADD = libtestdrvdriverdriver.la \
				   $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST += drvdriver_driver.h
