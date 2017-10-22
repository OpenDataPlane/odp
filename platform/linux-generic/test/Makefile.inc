include $(top_srcdir)/Makefile.inc

# The following definitions may be used by platform tests that wish to
# build specific ODP applications, (i.e those whose do more than validation
# test wrapping)

AM_LDFLAGS = -static

AM_CFLAGS = $(CUNIT_CFLAGS)

LIBCUNIT_COMMON = $(top_builddir)/test/common/libcunit_common.la
LIBODP = $(LIB)/libodphelper.la $(LIB)/libodp-linux.la $(DPDK_PMDS)

INCCUNIT_COMMON = -I$(top_srcdir)/test/common
