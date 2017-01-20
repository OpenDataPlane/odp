# The following definitions may be used by platform tests that wish to
# build specific ODP applications, (i.e those whose do more than validation
# test wrapping)

AM_LDFLAGS += -static

LIBCUNIT_COMMON = $(top_builddir)/test/common_plat/common/libcunit_common.la
LIB   = $(top_builddir)/lib
LIBODP = $(LIB)/libodphelper-@with_helper_platform@.la $(LIB)/libodp-linux.la

INCCUNIT_COMMON = -I$(top_srcdir)/test/common_plat/common
INCODP =  \
	 -I$(top_builddir)/include \
	 -I$(top_builddir)/platform/@with_platform@/include \
	 -I$(top_srcdir)/helper/include \
	 -I$(top_srcdir)/include \
	 -I$(top_srcdir)/platform/@with_platform@/arch/$(ARCH_DIR) \
	 -I$(top_srcdir)/platform/@with_platform@/include \
	 -I$(top_srcdir)/test
