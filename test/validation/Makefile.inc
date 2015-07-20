include $(top_srcdir)/test/Makefile.inc

COMMON_DIR = $(top_srcdir)/test/validation/common

AM_CFLAGS += -I$(COMMON_DIR)
AM_LDFLAGS += -static

LIBCUNIT_COMMON = $(COMMON_DIR)/libcunit_common.la
LIBCPUMASK_COMMON = $(COMMON_DIR)/libcpumask_common.la
LIBTHRMASK_COMMON = $(COMMON_DIR)/libthrmask_common.la
LIBODP = $(LIB)/libodphelper.la $(LIB)/libodp.la
