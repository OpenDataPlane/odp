include $(top_srcdir)/test/validation/Makefile.inc

AM_LDFLAGS += $(DPDK_PMDS)

AM_CFLAGS += $(CUNIT_CFLAGS)

