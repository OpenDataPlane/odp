include $(top_srcdir)/platform/Makefile.inc

AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/helper/include

include_HEADERS = \
		  $(top_srcdir)/include/odp.h

odpincludedir= $(includedir)/odp
odpinclude_HEADERS = \
		  $(srcdir)/include/odp/align.h \
		  $(srcdir)/include/odp/atomic.h \
		  $(srcdir)/include/odp/barrier.h \
		  $(srcdir)/include/odp/buffer.h \
		  $(srcdir)/include/odp/byteorder.h \
		  $(srcdir)/include/odp/classification.h \
		  $(srcdir)/include/odp/compiler.h \
		  $(srcdir)/include/odp/config.h \
		  $(srcdir)/include/odp/cpu.h \
		  $(srcdir)/include/odp/cpumask.h \
		  $(srcdir)/include/odp/crypto.h \
		  $(srcdir)/include/odp/debug.h \
		  $(srcdir)/include/odp/errno.h \
		  $(srcdir)/include/odp/event.h \
		  $(srcdir)/include/odp/hints.h \
		  $(srcdir)/include/odp/init.h \
		  $(srcdir)/include/odp/packet_flags.h \
		  $(srcdir)/include/odp/packet.h \
		  $(srcdir)/include/odp/packet_io.h \
		  $(srcdir)/include/odp/pool.h \
		  $(srcdir)/include/odp/queue.h \
		  $(srcdir)/include/odp/random.h \
		  $(srcdir)/include/odp/rwlock.h \
		  $(srcdir)/include/odp/schedule.h \
		  $(srcdir)/include/odp/schedule_types.h \
		  $(srcdir)/include/odp/shared_memory.h \
		  $(srcdir)/include/odp/spinlock.h \
		  $(srcdir)/include/odp/std_types.h \
		  $(srcdir)/include/odp/sync.h \
		  $(srcdir)/include/odp/system_info.h \
		  $(srcdir)/include/odp/thread.h \
		  $(srcdir)/include/odp/thrmask.h \
		  $(srcdir)/include/odp/ticketlock.h \
		  $(srcdir)/include/odp/time.h \
		  $(srcdir)/include/odp/timer.h \
		  $(srcdir)/include/odp/version.h

odpplatincludedir= $(includedir)/odp/plat
odpplatinclude_HEADERS = \
		  $(srcdir)/include/odp/plat/atomic_types.h \
		  $(srcdir)/include/odp/plat/barrier_types.h \
		  $(srcdir)/include/odp/plat/buffer_types.h \
		  $(srcdir)/include/odp/plat/byteorder_types.h \
		  $(srcdir)/include/odp/plat/classification_types.h \
		  $(srcdir)/include/odp/plat/cpumask_types.h \
		  $(srcdir)/include/odp/plat/crypto_types.h \
		  $(srcdir)/include/odp/plat/event_types.h \
		  $(srcdir)/include/odp/plat/packet_types.h \
		  $(srcdir)/include/odp/plat/packet_io_types.h \
		  $(srcdir)/include/odp/plat/pool_types.h \
		  $(srcdir)/include/odp/plat/queue_types.h \
		  $(srcdir)/include/odp/plat/rwlock_types.h \
		  $(srcdir)/include/odp/plat/schedule_types.h \
		  $(srcdir)/include/odp/plat/shared_memory_types.h \
		  $(srcdir)/include/odp/plat/spinlock_types.h \
		  $(srcdir)/include/odp/plat/strong_types.h \
		  $(srcdir)/include/odp/plat/thrmask_types.h \
		  $(srcdir)/include/odp/plat/ticketlock_types.h \
		  $(srcdir)/include/odp/plat/timer_types.h \
		  $(srcdir)/include/odp/plat/version_types.h

odpapiincludedir= $(includedir)/odp/api
odpapiinclude_HEADERS = \
		  $(top_srcdir)/include/odp/api/align.h \
		  $(top_srcdir)/include/odp/api/atomic.h \
		  $(top_srcdir)/include/odp/api/barrier.h \
		  $(top_srcdir)/include/odp/api/buffer.h \
		  $(top_srcdir)/include/odp/api/byteorder.h \
		  $(top_srcdir)/include/odp/api/classification.h \
		  $(top_srcdir)/include/odp/api/compiler.h \
		  $(top_srcdir)/include/odp/api/config.h \
		  $(top_srcdir)/include/odp/api/cpu.h \
		  $(top_srcdir)/include/odp/api/cpumask.h \
		  $(top_srcdir)/include/odp/api/crypto.h \
		  $(top_srcdir)/include/odp/api/debug.h \
		  $(top_srcdir)/include/odp/api/errno.h \
		  $(top_srcdir)/include/odp/api/event.h \
		  $(top_srcdir)/include/odp/api/hints.h \
		  $(top_srcdir)/include/odp/api/init.h \
		  $(top_srcdir)/include/odp/api/packet.h \
		  $(top_srcdir)/include/odp/api/packet_flags.h \
		  $(top_srcdir)/include/odp/api/packet_io.h \
		  $(top_srcdir)/include/odp/api/pool.h \
		  $(top_srcdir)/include/odp/api/queue.h \
		  $(top_srcdir)/include/odp/api/random.h \
		  $(top_srcdir)/include/odp/api/rwlock.h \
		  $(top_srcdir)/include/odp/api/schedule.h \
		  $(top_srcdir)/include/odp/api/schedule_types.h \
		  $(top_srcdir)/include/odp/api/shared_memory.h \
		  $(top_srcdir)/include/odp/api/spinlock.h \
		  $(top_srcdir)/include/odp/api/std_types.h \
		  $(top_srcdir)/include/odp/api/sync.h \
		  $(top_srcdir)/include/odp/api/system_info.h \
		  $(top_srcdir)/include/odp/api/thread.h \
		  $(top_srcdir)/include/odp/api/thrmask.h \
		  $(top_srcdir)/include/odp/api/ticketlock.h \
		  $(top_srcdir)/include/odp/api/time.h \
		  $(top_srcdir)/include/odp/api/timer.h \
		  $(top_srcdir)/include/odp/api/version.h

noinst_HEADERS = \
		  ${srcdir}/include/odp_align_internal.h \
		  ${srcdir}/include/odp_atomic_internal.h \
		  ${srcdir}/include/odp_buffer_inlines.h \
		  ${srcdir}/include/odp_buffer_internal.h \
		  ${srcdir}/include/odp_classification_datamodel.h \
		  ${srcdir}/include/odp_classification_inlines.h \
		  ${srcdir}/include/odp_classification_internal.h \
		  ${srcdir}/include/odp_crypto_internal.h \
		  ${srcdir}/include/odp_debug_internal.h \
		  ${srcdir}/include/odp_internal.h \
		  ${srcdir}/include/odp_packet_internal.h \
		  ${srcdir}/include/odp_packet_io_internal.h \
		  ${srcdir}/include/odp_packet_io_queue.h \
		  ${srcdir}/include/odp_packet_socket.h \
		  ${srcdir}/include/odp_pool_internal.h \
		  ${srcdir}/include/odp_queue_internal.h \
		  ${srcdir}/include/odp_schedule_internal.h \
		  ${srcdir}/include/odp_spin_internal.h \
		  ${srcdir}/include/odp_timer_internal.h \
		  ${srcdir}/Makefile.inc

__LIB__libodp_la_SOURCES = \
			   odp_barrier.c \
			   odp_buffer.c \
			   odp_classification.c \
			   odp_cpumask.c \
			   odp_crypto.c \
			   odp_errno.c \
			   odp_event.c \
			   odp_init.c \
			   odp_impl.c \
			   odp_packet.c \
			   odp_packet_flags.c \
			   odp_packet_io.c \
			   pktio/io_ops.c \
			   pktio/loop.c \
			   pktio/socket.c \
			   pktio/socket_mmap.c \
			   odp_pool.c \
			   odp_queue.c \
			   odp_rwlock.c \
			   odp_schedule.c \
			   odp_shared_memory.c \
			   odp_spinlock.c \
			   odp_system_info.c \
			   odp_thread.c \
			   odp_thrmask.c \
			   odp_ticketlock.c \
			   odp_time.c \
			   odp_timer.c \
			   odp_version.c \
			   odp_weak.c \
			   arch/@ARCH@/odp_time.c
