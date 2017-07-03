AM_CFLAGS   += -I$(top_srcdir)/platform/$(with_platform)/arch/$(ARCH_DIR)
AM_CXXFLAGS += -I$(top_srcdir)/platform/$(with_platform)/arch/$(ARCH_DIR)

empty:=
comma:= ,
space:= $(empty) $(empty)

PKTIO_OPS_MD := $(top_builddir)/lib/modules/pktio-ops/.libs

STATIC_PKTIO_OPS = $(PKTIO_OPS_MD)/ipc.a
STATIC_PKTIO_OPS += $(PKTIO_OPS_MD)/loopback.a
STATIC_PKTIO_OPS += $(wildcard $(PKTIO_OPS_MD)/pcap.a)
STATIC_PKTIO_OPS += $(PKTIO_OPS_MD)/socket.a
STATIC_PKTIO_OPS += $(PKTIO_OPS_MD)/socket-mmap.a
STATIC_PKTIO_OPS += $(PKTIO_OPS_MD)/tap.a

STATIC_PKTIO_OPS := --whole-archive $(STATIC_PKTIO_OPS) --no-whole-archive
STATIC_PKTIO_OPS_LDFLAGS := -Wl,$(subst $(space),$(comma),$(STATIC_PKTIO_OPS))
