IMPLEMENTATION_NAME="odp-dpdk"

ODP_VISIBILITY
ODP_ATOMIC

AM_CONDITIONAL([PKTIO_DPDK], [false])
ODP_PTHREAD
ODP_OPENSSL
ODP_TIMER

# Workaround issue in DPDK headers
ODP_CHECK_CFLAG([-Wimplicit-fallback=0])

# Set flat to get intrinsics to work
AS_IF([test "x${ARCH_DIR}" = "xx86"],
      [ODP_CHECK_CFLAG([-msse4.2])
       ODP_CHECK_CXXFLAG([-msse4.2])])

##########################################################################
# DPDK build variables
##########################################################################
DPDK_PATH=system
AC_ARG_WITH([dpdk-path],
[AS_HELP_STRING([--with-dpdk-path=DIR], [path to dpdk build directory])],
    [DPDK_PATH="$withval"])

ODP_DPDK([$DPDK_PATH], [],
     [AC_MSG_FAILURE([can't find DPDK])])

# Add DPDK include path, as packet_inlines.h uses rte_mbuf.h
AS_IF([test "x$ODP_ABI_COMPAT" != "x1"],
      [AS_VAR_APPEND([CPPFLAGS], " $DPDK_CPPFLAGS")
       ODP_DPDK_CFLAGS="$DPDK_CPPFLAGS"
       ODP_CHECK_CFLAG([-msse4.2],
		       [ODP_DPDK_CFLAGS="$ODP_DPDK_CFLAGS -msse4.2"])
       AC_SUBST([ODP_DPDK_CFLAGS])])

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([PLATFORM_IS_LINUX_DPDK],
	       [test "${with_platform}" = "linux-dpdk"])
AC_CONFIG_FILES([platform/linux-dpdk/Makefile
		 platform/linux-dpdk/libodp-linux.pc
		 platform/linux-dpdk/test/Makefile])
])
