ODP_IMPLEMENTATION_NAME="odp-linux"
ODP_LIB_NAME="odp-linux"

ODP_VISIBILITY
ODP_ATOMIC

ODP_PTHREAD
ODP_TIMER
m4_include([platform/linux-generic/m4/odp_pcap.m4])
m4_include([platform/linux-generic/m4/odp_scheduler.m4])

AC_ARG_WITH([pcap],
	    [AS_HELP_STRING([--without-pcap],
			    [compile without PCAP])],
	    [],
	    [with_pcap=yes])
AS_IF([test "x$with_pcap" != xno],
      [ODP_PCAP([with_pcap=yes]‚[with_pcap=no])])
AM_CONDITIONAL([ODP_PKTIO_PCAP], [test x$have_pcap = xyes])

m4_include([platform/linux-generic/m4/odp_libconfig.m4])
m4_include([platform/linux-generic/m4/odp_pcapng.m4])
m4_include([platform/linux-generic/m4/odp_netmap.m4])
m4_include([platform/linux-generic/m4/odp_dpdk.m4])
ODP_SCHEDULER

AS_VAR_APPEND([PLAT_DEP_LIBS], ["${LIBCONFIG_LIBS} ${OPENSSL_LIBS} ${DPDK_LIBS_LT}"])

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([PLATFORM_IS_LINUX_GENERIC],
	       [test "${with_platform}" = "linux-generic"])
AC_CONFIG_FILES([platform/linux-generic/Makefile
		 platform/linux-generic/libodp-linux.pc
		 platform/linux-generic/dumpconfig/Makefile
		 platform/linux-generic/test/Makefile
		 platform/linux-generic/test/validation/api/shmem/Makefile
		 platform/linux-generic/test/validation/api/pktio/Makefile
		 platform/linux-generic/test/pktio_ipc/Makefile])
])
