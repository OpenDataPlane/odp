# The following definitions may be used by platform tests that wish to
# build specific ODP applications, (i.e those whose do more than validation
# test wrapping)

AM_LDFLAGS = -static

AM_CFLAGS = $(CUNIT_CFLAGS)

LIBCUNIT_COMMON = $(top_builddir)/test/common/libcunit_common.la
LIB   = $(top_builddir)/lib
LIBODP = $(LIB)/libodphelper.la $(LIB)/libodp-dpdk.la

INCCUNIT_COMMON = -I$(top_srcdir)/test/common
INCODP =  \
	 -I$(top_builddir)/include \
	 -I$(top_builddir)/platform/@with_platform@/include \
	 -I$(top_srcdir)/helper/include \
	 -I$(top_srcdir)/include \
	 -I$(top_srcdir)/include/odp/arch/@ARCH_ABI@ \
	 -I$(top_srcdir)/platform/@with_platform@/arch/$(ARCH_DIR) \
	 -I$(top_srcdir)/platform/@with_platform@/include \
	 -I$(top_srcdir)/test
