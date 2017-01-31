LIB   = $(top_builddir)/lib

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(top_builddir)/pkgconfig/libodp-linux.pc

.PHONY: pkgconfig/libodp-linux.pc

VPATH = $(srcdir) $(builddir)
lib_LTLIBRARIES = $(LIB)/libodp-linux.la

AM_LDFLAGS += -version-number '$(ODP_LIBSO_VERSION)'

AM_CFLAGS += "-DGIT_HASH=$(VERSION)"
AM_CFLAGS += $(VISIBILITY_CFLAGS)

#The implementation will need to retain the deprecated implementation
AM_CFLAGS += -Wno-deprecated-declarations

odpapispecincludedir= $(includedir)/odp/api/spec
odpapispecinclude_HEADERS = \
		  $(top_srcdir)/include/odp/api/spec/align.h \
		  $(top_srcdir)/include/odp/api/spec/atomic.h \
		  $(top_srcdir)/include/odp/api/spec/barrier.h \
		  $(top_srcdir)/include/odp/api/spec/buffer.h \
		  $(top_srcdir)/include/odp/api/spec/byteorder.h \
		  $(top_srcdir)/include/odp/api/spec/classification.h \
		  $(top_srcdir)/include/odp/api/spec/compiler.h \
		  $(top_srcdir)/include/odp/api/spec/cpu.h \
		  $(top_srcdir)/include/odp/api/spec/cpumask.h \
		  $(top_srcdir)/include/odp/api/spec/crypto.h \
		  $(top_srcdir)/include/odp/api/spec/debug.h \
		  $(top_srcdir)/include/odp/api/spec/errno.h \
		  $(top_srcdir)/include/odp/api/spec/event.h \
		  $(top_srcdir)/include/odp/api/spec/hash.h \
		  $(top_srcdir)/include/odp/api/spec/hints.h \
		  $(top_srcdir)/include/odp/api/spec/init.h \
		  $(top_srcdir)/include/odp/api/spec/packet.h \
		  $(top_srcdir)/include/odp/api/spec/packet_flags.h \
		  $(top_srcdir)/include/odp/api/spec/packet_io.h \
		  $(top_srcdir)/include/odp/api/spec/packet_io_stats.h \
		  $(top_srcdir)/include/odp/api/spec/pool.h \
		  $(top_srcdir)/include/odp/api/spec/queue.h \
		  $(top_srcdir)/include/odp/api/spec/random.h \
		  $(top_srcdir)/include/odp/api/spec/rwlock.h \
		  $(top_srcdir)/include/odp/api/spec/rwlock_recursive.h \
		  $(top_srcdir)/include/odp/api/spec/schedule.h \
		  $(top_srcdir)/include/odp/api/spec/schedule_types.h \
		  $(top_srcdir)/include/odp/api/spec/shared_memory.h \
		  $(top_srcdir)/include/odp/api/spec/spinlock.h \
		  $(top_srcdir)/include/odp/api/spec/spinlock_recursive.h \
		  $(top_srcdir)/include/odp/api/spec/std_clib.h \
		  $(top_srcdir)/include/odp/api/spec/std_types.h \
		  $(top_srcdir)/include/odp/api/spec/sync.h \
		  $(top_srcdir)/include/odp/api/spec/system_info.h \
		  $(top_srcdir)/include/odp/api/spec/thread.h \
		  $(top_srcdir)/include/odp/api/spec/thrmask.h \
		  $(top_srcdir)/include/odp/api/spec/ticketlock.h \
		  $(top_srcdir)/include/odp/api/spec/time.h \
		  $(top_srcdir)/include/odp/api/spec/timer.h \
		  $(top_builddir)/include/odp/api/spec/version.h \
		  $(top_srcdir)/include/odp/api/spec/traffic_mngr.h

odpapiabidefaultincludedir= $(includedir)/odp/arch/default/api/abi
odpapiabidefaultinclude_HEADERS = \
	$(top_srcdir)/include/odp/arch/default/api/abi/buffer.h \
	$(top_srcdir)/include/odp/arch/default/api/abi/classification.h \
	$(top_srcdir)/include/odp/arch/default/api/abi/crypto.h \
	$(top_srcdir)/include/odp/arch/default/api/abi/event.h \
	$(top_srcdir)/include/odp/arch/default/api/abi/packet.h \
	$(top_srcdir)/include/odp/arch/default/api/abi/pool.h

odpapiabiarchincludedir= $(includedir)/odp/arch/@ARCH_ABI@/odp/api/abi
odpapiabiarchinclude_HEADERS = \
	$(top_srcdir)/include/odp/arch/@ARCH_ABI@/odp/api/abi/buffer.h \
	$(top_srcdir)/include/odp/arch/@ARCH_ABI@/odp/api/abi/classification.h \
	$(top_srcdir)/include/odp/arch/@ARCH_ABI@/odp/api/abi/crypto.h \
	$(top_srcdir)/include/odp/arch/@ARCH_ABI@/odp/api/abi/event.h \
	$(top_srcdir)/include/odp/arch/@ARCH_ABI@/odp/api/abi/packet.h \
	$(top_srcdir)/include/odp/arch/@ARCH_ABI@/odp/api/abi/pool.h

EXTRA_DIST = \
	     arch/arm/odp/api/cpu_arch.h \
	     arch/arm/odp_cpu_arch.c \
	     arch/arm/odp_sysinfo_parse.c \
	     arch/default/odp/api/cpu_arch.h \
	     arch/default/odp_cpu_arch.c \
	     arch/default/odp_sysinfo_parse.c \
	     arch/mips64/odp/api/cpu_arch.h \
	     arch/mips64/odp_cpu_arch.c \
	     arch/mips64/odp_sysinfo_parse.c \
	     arch/powerpc/odp/api/cpu_arch.h \
	     arch/powerpc/odp_cpu_arch.c \
	     arch/powerpc/odp_sysinfo_parse.c \
	     arch/x86/odp/api/cpu_arch.h \
	     arch/x86/odp_cpu_arch.c \
	     arch/x86/odp_sysinfo_parse.c
