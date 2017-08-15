include $(top_srcdir)/test/Makefile.inc

COMMON_DIR = $(top_builddir)/test/common_plat/common

AM_CFLAGS += -I$(top_srcdir)/test/common_plat/common
AM_LDFLAGS += -static
AM_LDFLAGS += $(DPDK_PMDS)

AM_CPPFLAGS += $(CUNIT_CPPFLAGS)

LIBCUNIT_COMMON = $(COMMON_DIR)/libcunit_common.la
LIBCPUMASK_COMMON = $(COMMON_DIR)/libcpumask_common.la
LIBTHRMASK_COMMON = $(COMMON_DIR)/libthrmask_common.la
LIBODP = $(LIB)/libodphelper.la $(LIB)/libodp-linux.la
