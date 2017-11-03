IMPLEMENTATION_NAME="odp-linux"

dnl Check for libconfig (required)
PKG_CHECK_MODULES([LIBCONFIG], [libconfig >= 1.3.2])

ODP_VISIBILITY
ODP_ATOMIC

m4_include([platform/linux-generic/m4/odp_pthread.m4])
ODP_TIMER
ODP_OPENSSL
m4_include([platform/linux-generic/m4/odp_pcap.m4])
m4_include([platform/linux-generic/m4/odp_modules.m4])
m4_include([platform/linux-generic/m4/odp_netmap.m4])
m4_include([platform/linux-generic/m4/odp_dpdk.m4])
m4_include([platform/linux-generic/m4/odp_schedule.m4])

m4_include([platform/linux-generic/m4/performance.m4])

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([PLATFORM_IS_LINUX_GENERIC],
	       [test "${with_platform}" = "linux-generic"])
])

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

##########################################################################
# Enable default pktios build
##########################################################################
AC_DEFINE([ODP_PKTIO_IPC], [1],
	      [Define to 1 to enable IPC packet I/O support])

AC_DEFINE([ODP_PKTIO_TAP], [1],
	      [Define to 1 to enable TAP packet I/O support])

AC_DEFINE([ODP_PKTIO_SOCKET], [1],
	      [Define to 1 to enable SOCKET packet I/O support])

AC_DEFINE([ODP_PKTIO_SOCKET_MMAP], [1],
	      [Define to 1 to enable SOCKET_MMAP packet I/O support])
