include_HEADERS = \
		  odp.h \
		  odp_api.h

odpapispecincludedir= $(includedir)/odp/api/spec
odpapispecinclude_HEADERS = \
		  odp/api/spec/align.h \
		  odp/api/spec/atomic.h \
		  odp/api/spec/barrier.h \
		  odp/api/spec/buffer.h \
		  odp/api/spec/byteorder.h \
		  odp/api/spec/chksum.h \
		  odp/api/spec/classification.h \
		  odp/api/spec/compiler.h \
		  odp/api/spec/cpu.h \
		  odp/api/spec/cpumask.h \
		  odp/api/spec/crypto.h \
		  odp/api/spec/debug.h \
		  odp/api/spec/errno.h \
		  odp/api/spec/event.h \
		  odp/api/spec/feature.h \
		  odp/api/spec/hash.h \
		  odp/api/spec/hints.h \
		  odp/api/spec/init.h \
		  odp/api/spec/ipsec.h \
		  odp/api/spec/packet.h \
		  odp/api/spec/packet_flags.h \
		  odp/api/spec/packet_io.h \
		  odp/api/spec/packet_io_stats.h \
		  odp/api/spec/pool.h \
		  odp/api/spec/queue.h \
		  odp/api/spec/random.h \
		  odp/api/spec/rwlock.h \
		  odp/api/spec/rwlock_recursive.h \
		  odp/api/spec/schedule.h \
		  odp/api/spec/schedule_types.h \
		  odp/api/spec/shared_memory.h \
		  odp/api/spec/spinlock.h \
		  odp/api/spec/spinlock_recursive.h \
		  odp/api/spec/std_clib.h \
		  odp/api/spec/std_types.h \
		  odp/api/spec/support.h \
		  odp/api/spec/sync.h \
		  odp/api/spec/system_info.h \
		  odp/api/spec/thread.h \
		  odp/api/spec/threshold.h \
		  odp/api/spec/thrmask.h \
		  odp/api/spec/ticketlock.h \
		  odp/api/spec/time.h \
		  odp/api/spec/timer.h \
		  odp/api/spec/traffic_mngr.h

nodist_odpapispecinclude_HEADERS = \
		  odp/api/spec/deprecated.h \
		  odp/api/spec/version.h

odpapiabidefaultincludedir= $(includedir)/odp/api/abi-default
odpapiabidefaultinclude_HEADERS = \
	odp/api/abi-default/barrier.h \
	odp/api/abi-default/buffer.h \
	odp/api/abi-default/classification.h \
	odp/api/abi-default/cpumask.h \
	odp/api/abi-default/crypto.h \
	odp/api/abi-default/event.h \
	odp/api/abi-default/init.h \
	odp/api/abi-default/ipsec.h \
	odp/api/abi-default/packet.h \
	odp/api/abi-default/packet_io.h \
	odp/api/abi-default/pool.h \
	odp/api/abi-default/queue.h \
	odp/api/abi-default/rwlock.h \
	odp/api/abi-default/rwlock_recursive.h \
	odp/api/abi-default/shared_memory.h \
	odp/api/abi-default/version.h

# Insall ABI headers only if required
if ODP_ABI_COMPAT

odpapiabiarchincludedir = $(archincludedir)/odp/api/abi
if ARCH_IS_ARM
odpapiabiarchinclude_HEADERS = \
	odp/arch/arm32-linux/odp/api/abi/barrier.h \
	odp/arch/arm32-linux/odp/api/abi/buffer.h \
	odp/arch/arm32-linux/odp/api/abi/classification.h \
	odp/arch/arm32-linux/odp/api/abi/cpumask.h \
	odp/arch/arm32-linux/odp/api/abi/crypto.h \
	odp/arch/arm32-linux/odp/api/abi/event.h \
	odp/arch/arm32-linux/odp/api/abi/init.h \
	odp/arch/arm32-linux/odp/api/abi/ipsec.h \
	odp/arch/arm32-linux/odp/api/abi/packet.h \
	odp/arch/arm32-linux/odp/api/abi/packet_io.h \
	odp/arch/arm32-linux/odp/api/abi/pool.h \
	odp/arch/arm32-linux/odp/api/abi/queue.h \
	odp/arch/arm32-linux/odp/api/abi/rwlock.h \
	odp/arch/arm32-linux/odp/api/abi/rwlock_recursive.h \
	odp/arch/arm32-linux/odp/api/abi/shared_memory.h \
	odp/arch/arm32-linux/odp/api/abi/version.h
endif
if ARCH_IS_AARCH64
odpapiabiarchinclude_HEADERS = \
	odp/arch/arm64-linux/odp/api/abi/barrier.h \
	odp/arch/arm64-linux/odp/api/abi/buffer.h \
	odp/arch/arm64-linux/odp/api/abi/classification.h \
	odp/arch/arm64-linux/odp/api/abi/cpumask.h \
	odp/arch/arm64-linux/odp/api/abi/crypto.h \
	odp/arch/arm64-linux/odp/api/abi/event.h \
	odp/arch/arm64-linux/odp/api/abi/init.h \
	odp/arch/arm64-linux/odp/api/abi/ipsec.h \
	odp/arch/arm64-linux/odp/api/abi/packet.h \
	odp/arch/arm64-linux/odp/api/abi/packet_io.h \
	odp/arch/arm64-linux/odp/api/abi/pool.h \
	odp/arch/arm64-linux/odp/api/abi/queue.h \
	odp/arch/arm64-linux/odp/api/abi/rwlock.h \
	odp/arch/arm64-linux/odp/api/abi/rwlock_recursive.h \
	odp/arch/arm64-linux/odp/api/abi/shared_memory.h \
	odp/arch/arm64-linux/odp/api/abi/version.h
endif
if ARCH_IS_MIPS64
odpapiabiarchinclude_HEADERS = \
	odp/arch/mips64-linux/odp/api/abi/barrier.h \
	odp/arch/mips64-linux/odp/api/abi/buffer.h \
	odp/arch/mips64-linux/odp/api/abi/classification.h \
	odp/arch/mips64-linux/odp/api/abi/cpumask.h \
	odp/arch/mips64-linux/odp/api/abi/crypto.h \
	odp/arch/mips64-linux/odp/api/abi/event.h \
	odp/arch/mips64-linux/odp/api/abi/init.h \
	odp/arch/mips64-linux/odp/api/abi/ipsec.h \
	odp/arch/mips64-linux/odp/api/abi/packet.h \
	odp/arch/mips64-linux/odp/api/abi/packet_io.h \
	odp/arch/mips64-linux/odp/api/abi/pool.h \
	odp/arch/mips64-linux/odp/api/abi/queue.h \
	odp/arch/mips64-linux/odp/api/abi/rwlock.h \
	odp/arch/mips64-linux/odp/api/abi/rwlock_recursive.h \
	odp/arch/mips64-linux/odp/api/abi/shared_memory.h \
	odp/arch/mips64-linux/odp/api/abi/version.h
endif
if ARCH_IS_POWERPC
odpapiabiarchinclude_HEADERS = \
	odp/arch/power64-linux/odp/api/abi/barrier.h \
	odp/arch/power64-linux/odp/api/abi/buffer.h \
	odp/arch/power64-linux/odp/api/abi/classification.h \
	odp/arch/power64-linux/odp/api/abi/cpumask.h \
	odp/arch/power64-linux/odp/api/abi/crypto.h \
	odp/arch/power64-linux/odp/api/abi/event.h \
	odp/arch/power64-linux/odp/api/abi/init.h \
	odp/arch/power64-linux/odp/api/abi/ipsec.h \
	odp/arch/power64-linux/odp/api/abi/packet.h \
	odp/arch/power64-linux/odp/api/abi/packet_io.h \
	odp/arch/power64-linux/odp/api/abi/pool.h \
	odp/arch/power64-linux/odp/api/abi/queue.h \
	odp/arch/power64-linux/odp/api/abi/rwlock.h \
	odp/arch/power64-linux/odp/api/abi/rwlock_recursive.h \
	odp/arch/power64-linux/odp/api/abi/shared_memory.h \
	odp/arch/power64-linux/odp/api/abi/version.h
endif
if ARCH_IS_X86_32
odpapiabiarchinclude_HEADERS = \
	odp/arch/x86_32-linux/odp/api/abi/barrier.h \
	odp/arch/x86_32-linux/odp/api/abi/buffer.h \
	odp/arch/x86_32-linux/odp/api/abi/classification.h \
	odp/arch/x86_32-linux/odp/api/abi/cpumask.h \
	odp/arch/x86_32-linux/odp/api/abi/crypto.h \
	odp/arch/x86_32-linux/odp/api/abi/event.h \
	odp/arch/x86_32-linux/odp/api/abi/init.h \
	odp/arch/x86_32-linux/odp/api/abi/ipsec.h \
	odp/arch/x86_32-linux/odp/api/abi/packet.h \
	odp/arch/x86_32-linux/odp/api/abi/packet_io.h \
	odp/arch/x86_32-linux/odp/api/abi/pool.h \
	odp/arch/x86_32-linux/odp/api/abi/queue.h \
	odp/arch/x86_32-linux/odp/api/abi/rwlock.h \
	odp/arch/x86_32-linux/odp/api/abi/rwlock_recursive.h \
	odp/arch/x86_32-linux/odp/api/abi/shared_memory.h \
	odp/arch/x86_32-linux/odp/api/abi/version.h
endif
if ARCH_IS_X86_64
odpapiabiarchinclude_HEADERS = \
	odp/arch/x86_64-linux/odp/api/abi/barrier.h \
	odp/arch/x86_64-linux/odp/api/abi/buffer.h \
	odp/arch/x86_64-linux/odp/api/abi/classification.h \
	odp/arch/x86_64-linux/odp/api/abi/cpumask.h \
	odp/arch/x86_64-linux/odp/api/abi/crypto.h \
	odp/arch/x86_64-linux/odp/api/abi/event.h \
	odp/arch/x86_64-linux/odp/api/abi/init.h \
	odp/arch/x86_64-linux/odp/api/abi/ipsec.h \
	odp/arch/x86_64-linux/odp/api/abi/packet.h \
	odp/arch/x86_64-linux/odp/api/abi/packet_io.h \
	odp/arch/x86_64-linux/odp/api/abi/pool.h \
	odp/arch/x86_64-linux/odp/api/abi/queue.h \
	odp/arch/x86_64-linux/odp/api/abi/rwlock.h \
	odp/arch/x86_64-linux/odp/api/abi/rwlock_recursive.h \
	odp/arch/x86_64-linux/odp/api/abi/shared_memory.h \
	odp/arch/x86_64-linux/odp/api/abi/version.h
endif
endif # ODP_ABI_COMPAT

# Rerefence all nodist_*_HEADERS here
.PHONY: $(nodist_odpapispecinclude_HEADERS)
$(nodist_odpapispecinclude_HEADERS):
	$(MAKE) -C $(top_builddir) $(subdir)/$@
