MODULES = $(top_builddir)/lib/modules/pktio-ops

AM_CFLAGS +=  -I$(srcdir)
AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include/odp/arch/@ARCH_ABI@
AM_CFLAGS +=  -I$(top_srcdir)/platform/@with_platform@/include
AM_CFLAGS +=  -I$(top_srcdir)/platform/@with_platform@/arch/@ARCH_DIR@
AM_CFLAGS +=  -I$(top_srcdir)/frameworks/modular
AM_CFLAGS +=  -I$(top_builddir)/include

lib_LTLIBRARIES  = $(MODULES)/ipc.la

__MODULES__ipc_la_SOURCES = ipc.c
__MODULES__ipc_la_LDFLAGS = -module -avoid-version

lib_LTLIBRARIES += $(MODULES)/loopback.la

__MODULES__loopback_la_SOURCES = loopback.c
__MODULES__loopback_la_LDFLAGS = -module -avoid-version

lib_LTLIBRARIES += $(MODULES)/socket.la

__MODULES__socket_la_SOURCES = socket.c
__MODULES__socket_la_LDFLAGS = -module -avoid-version

lib_LTLIBRARIES += $(MODULES)/socket-mmap.la

__MODULES__socket_mmap_la_SOURCES = socket_mmap.c
__MODULES__socket_mmap_la_LDFLAGS = -module -avoid-version

lib_LTLIBRARIES += $(MODULES)/tap.la

__MODULES__tap_la_SOURCES = tap.c
__MODULES__tap_la_LDFLAGS = -module -avoid-version

if HAVE_PCAP
lib_LTLIBRARIES += $(MODULES)/pcap.la

__MODULES__pcap_la_SOURCES = pcap.c
__MODULES__pcap_la_LDFLAGS = -module -avoid-version
endif
