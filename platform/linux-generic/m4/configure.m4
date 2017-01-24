IMPLEMENTATION_NAME="odp-linux"

ODP_VISIBILITY
ODP_ATOMIC

# Check for libconfig (required)
AC_CHECK_HEADERS([libconfig.h], HEADER_LIBCONFIG="yes")
PKG_CHECK_MODULES([PKGCONFIG], [libconfig >= 1.3.2], LIBRARY_LIBCONFIG="yes")
if test "x$LIBRARY_LIBCONFIG" != "x" && test "x$HEADER_LIBCONFIG" != "x" ; then
    CFLAGS="$CFLAGS $PKGCONFIG_CFLAGS"
    LIBS="$LIBS $PKGCONFIG_LIBS"
    AM_CPPFLAGS="$AM_CPPFLAGS `pkg-config --cflags-only-I libconfig`"
else
    AC_MSG_FAILURE([libconfig not found (required)])
fi

m4_include([platform/linux-generic/m4/odp_pthread.m4])
ODP_TIMER
ODP_OPENSSL
m4_include([platform/linux-generic/m4/odp_pcap.m4])
m4_include([platform/linux-generic/m4/odp_netmap.m4])
m4_include([platform/linux-generic/m4/odp_dpdk.m4])
m4_include([platform/linux-generic/m4/odp_schedule.m4])

m4_include([platform/linux-generic/m4/performance.m4])

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([PLATFORM_IS_LINUX_GENERIC],
	       [test "${with_platform}" = "linux-generic"])
AC_CONFIG_FILES([platform/linux-generic/Makefile
		 platform/linux-generic/libodp-linux.pc
		 platform/linux-generic/include/odp/api/plat/static_inline.h
		 platform/linux-generic/test/Makefile
		 platform/linux-generic/test/validation/api/shmem/Makefile
		 platform/linux-generic/test/validation/api/pktio/Makefile
		 platform/linux-generic/test/mmap_vlan_ins/Makefile
		 platform/linux-generic/test/pktio_ipc/Makefile
		 platform/linux-generic/test/ring/Makefile
		 platform/linux-generic/test/performance/Makefile])
])
