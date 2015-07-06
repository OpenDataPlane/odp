include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(top_srcdir)/test/validation/common
AM_LDFLAGS += -static

LIBCUNIT_COMMON = $(top_builddir)/test/validation/common/libcunit_common.a
LIBODP = $(LIB)/libodphelper.la $(LIB)/libodp.la
