AM_CFLAGS   += -I$(top_srcdir)/platform/$(with_platform)/arch/$(ARCH_DIR)
AM_CXXFLAGS += -I$(top_srcdir)/platform/$(with_platform)/arch/$(ARCH_DIR)
AM_LDFLAGS += -R$(SDK_INSTALL_PATH)/lib
LOG_COMPILER = $(top_srcdir)/test/linux-dpdk/wrapper-script.sh
