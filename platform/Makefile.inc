LIB   = $(top_builddir)/lib

dist_pkgdata_DATA = $(LIB)/libodp.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(top_builddir)/pkgconfig/libodp.pc

.PHONY: pkgconfig/libodp.pc

VPATH = $(srcdir) $(builddir)
lib_LTLIBRARIES = $(LIB)/libodp.la

AM_LDFLAGS += -version-number '$(ODP_LIBSO_VERSION)'

GIT_DESC = `$(top_srcdir)/scripts/get_impl_str.sh $(top_srcdir)`
AM_CFLAGS += "-DGIT_HASH=$(GIT_DESC)"
AM_CFLAGS += -DPLATFORM=${with_platform}

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
		  $(top_srcdir)/include/odp/api/spec/config.h \
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
		  $(top_srcdir)/include/odp/api/spec/version.h
