AM_CFLAGS   += -I$(top_srcdir)/platform/$(with_platform)/arch/$(ARCH_DIR)
AM_CXXFLAGS += -I$(top_srcdir)/platform/$(with_platform)/arch/$(ARCH_DIR)
AM_CPPFLAGS += $(DPDK_CPPFLAGS)
AM_LDFLAGS += $(DPDK_LDFLAGS)
LOG_COMPILER = $(top_srcdir)/platform/linux-dpdk/test/wrapper-script.sh
SH_LOG_COMPILER = $(LOG_COMPILER)
