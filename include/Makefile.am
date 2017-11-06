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

odpapiabidefaultincludedir= $(includedir)/odp/arch/default/api/abi
odpapiabidefaultinclude_HEADERS = \
	odp/arch/default/api/abi/buffer.h \
	odp/arch/default/api/abi/classification.h \
	odp/arch/default/api/abi/crypto.h \
	odp/arch/default/api/abi/event.h \
	odp/arch/default/api/abi/packet.h \
	odp/arch/default/api/abi/pool.h \
	odp/arch/default/api/abi/queue.h \
	odp/arch/default/api/abi/shared_memory.h

odpapiabiarchincludedir= $(includedir)/odp/arch/@ARCH_ABI@/odp/api/abi
if ARCH_IS_ARM
odpapiabiarchinclude_HEADERS = \
	odp/arch/arm32-linux/odp/api/abi/buffer.h \
	odp/arch/arm32-linux/odp/api/abi/classification.h \
	odp/arch/arm32-linux/odp/api/abi/crypto.h \
	odp/arch/arm32-linux/odp/api/abi/event.h \
	odp/arch/arm32-linux/odp/api/abi/packet.h \
	odp/arch/arm32-linux/odp/api/abi/pool.h \
	odp/arch/arm32-linux/odp/api/abi/queue.h \
	odp/arch/arm32-linux/odp/api/abi/shared_memory.h
endif
if ARCH_IS_AARCH64
odpapiabiarchinclude_HEADERS = \
	odp/arch/arm64-linux/odp/api/abi/buffer.h \
	odp/arch/arm64-linux/odp/api/abi/classification.h \
	odp/arch/arm64-linux/odp/api/abi/crypto.h \
	odp/arch/arm64-linux/odp/api/abi/event.h \
	odp/arch/arm64-linux/odp/api/abi/packet.h \
	odp/arch/arm64-linux/odp/api/abi/pool.h \
	odp/arch/arm64-linux/odp/api/abi/queue.h \
	odp/arch/arm64-linux/odp/api/abi/shared_memory.h
endif
if ARCH_IS_MIPS64
odpapiabiarchinclude_HEADERS = \
	odp/arch/mips64-linux/odp/api/abi/buffer.h \
	odp/arch/mips64-linux/odp/api/abi/classification.h \
	odp/arch/mips64-linux/odp/api/abi/crypto.h \
	odp/arch/mips64-linux/odp/api/abi/event.h \
	odp/arch/mips64-linux/odp/api/abi/packet.h \
	odp/arch/mips64-linux/odp/api/abi/pool.h \
	odp/arch/mips64-linux/odp/api/abi/queue.h \
	odp/arch/mips64-linux/odp/api/abi/shared_memory.h
endif
if ARCH_IS_POWERPC
odpapiabiarchinclude_HEADERS = \
	odp/arch/power64-linux/odp/api/abi/buffer.h \
	odp/arch/power64-linux/odp/api/abi/classification.h \
	odp/arch/power64-linux/odp/api/abi/crypto.h \
	odp/arch/power64-linux/odp/api/abi/event.h \
	odp/arch/power64-linux/odp/api/abi/packet.h \
	odp/arch/power64-linux/odp/api/abi/pool.h \
	odp/arch/power64-linux/odp/api/abi/queue.h \
	odp/arch/power64-linux/odp/api/abi/shared_memory.h
endif
if ARCH_IS_X86_32
odpapiabiarchinclude_HEADERS = \
	odp/arch/x86_32-linux/odp/api/abi/buffer.h \
	odp/arch/x86_32-linux/odp/api/abi/classification.h \
	odp/arch/x86_32-linux/odp/api/abi/crypto.h \
	odp/arch/x86_32-linux/odp/api/abi/event.h \
	odp/arch/x86_32-linux/odp/api/abi/packet.h \
	odp/arch/x86_32-linux/odp/api/abi/pool.h \
	odp/arch/x86_32-linux/odp/api/abi/queue.h \
	odp/arch/x86_32-linux/odp/api/abi/shared_memory.h
endif
if ARCH_IS_X86_64
odpapiabiarchinclude_HEADERS = \
	odp/arch/x86_64-linux/odp/api/abi/buffer.h \
	odp/arch/x86_64-linux/odp/api/abi/classification.h \
	odp/arch/x86_64-linux/odp/api/abi/crypto.h \
	odp/arch/x86_64-linux/odp/api/abi/event.h \
	odp/arch/x86_64-linux/odp/api/abi/packet.h \
	odp/arch/x86_64-linux/odp/api/abi/pool.h \
	odp/arch/x86_64-linux/odp/api/abi/queue.h \
	odp/arch/x86_64-linux/odp/api/abi/shared_memory.h
endif

# Create symlink for ABI header files. Application does not need to use the arch
# specific include path for installed files.
install-data-hook:
	if [ -h $(DESTDIR)$(prefix)/include/odp/api/abi ]; then \
		: ; \
	else \
		$(LN_S) -rf $(DESTDIR)$(prefix)/include/odp/arch/@ARCH_ABI@/odp/api/abi \
			$(DESTDIR)$(prefix)/include/odp/api/abi; \
	fi

# Rerefence all nodist_*_HEADERS here
.PHONY: $(nodist_odpapispecinclude_HEADERS)
$(nodist_odpapispecinclude_HEADERS):
	$(MAKE) -C $(top_builddir) $(subdir)/$@
