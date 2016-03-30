# The following definitions may be used by platform tests that wish to
# build specific ODP applications, (i.e those whose do more than validation
# test wrapping)

AM_LDFLAGS += -static

LIBCUNIT_COMMON = $(top_builddir)/test/validation/common/libcunit_common.la
LIB   = $(top_builddir)/lib
LIBODP = $(LIB)/libodphelper-linux.la $(LIB)/libodp-dpdk.la

INCCUNIT_COMMON = -I$(top_srcdir)/test/validation/common
INCODP = -I$(top_srcdir)/test \
	 -I$(top_srcdir)/platform/@with_platform@/include \
	 -I$(top_srcdir)/platform/@with_platform@/arch/$(ARCH) \
	 -I$(top_srcdir)/include \
	 -I$(top_srcdir)/helper/include
