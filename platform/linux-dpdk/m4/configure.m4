IMPLEMENTATION_NAME="odp-dpdk"

ODP_VISIBILITY
ODP_ATOMIC

# linux-generic PCAP support is not relevant as the code doesn't use
# linux-generic pktio at all. And DPDK has its own PCAP support anyway
AM_CONDITIONAL([HAVE_PCAP], [false])
m4_include([platform/linux-dpdk/m4/odp_pthread.m4])
ODP_TIMER
ODP_OPENSSL
m4_include([platform/linux-dpdk/m4/odp_schedule.m4])

##########################################################################
# Set DPDK install path
##########################################################################
AC_ARG_WITH([dpdk-path],
[AS_HELP_STRING([--with-dpdk-path=DIR], [path to dpdk build directory])],
    [DPDK_PATH="$withval"
     pktio_dpdk_support=yes],[])


AS_CASE($host_cpu, [x86_64], [DPDK_CPPFLAGS="-msse4.2"])
AS_IF([test "x$DPDK_PATH" = "xsystem"],
      [DPDK_CPPFLAGS="$DPDK_CPPFLAGS -isystem/usr/include/dpdk"
       DPDK_LDFLAGS=""
       DPDK_PMD_PATH="`$CC --print-file-name=librte_pmd_null.a`"
       DPDK_PMD_PATH="`dirname "$DPDK_PMD_PATH"`"
       AS_IF([test "x$DPDK_PMD_PATH" = "x"],
	     [AC_MSG_FAILURE([Could not locate system DPDK PMD directory])])],
      [DPDK_CPPFLAGS="$DPDK_CPPFLAGS -isystem $DPDK_PATH/include"
       DPDK_LDFLAGS="-L$DPDK_PATH/lib"
       DPDK_PMD_PATH="$DPDK_PATH/lib"])

##########################################################################
# Check for DPDK availability
#
# DPDK pmd drivers are not linked unless the --whole-archive option is
# used. No spaces are allowed between the --whole-arhive flags.
##########################################################################

ODP_DPDK_CHECK([$DPDK_CPPFLAGS], [$DPDK_LDFLAGS], [],
               [AC_MSG_FAILURE([can't find DPDK])])

ODP_DPDK_PMDS([$DPDK_PMD_PATH])

AC_DEFINE([ODP_PKTIO_DPDK], [1],
	  [Define to 1 to enable DPDK packet I/O support])
AC_DEFINE_UNQUOTED([ODP_DPDK_ZERO_COPY], [$zero_copy],
	  [Define to 1 to enable DPDK zero copy support])

if test -r "$DPDK_PMD_PATH/librte_pmd_pcap.a" &&
   ! test -r "$DPDK_PMD_PATH/librte_pmd_pcap.so" ; then
    DPDK_LIBS="$DPDK_LIBS -lpcap"
fi

AC_SUBST([DPDK_LDFLAGS])
AC_SUBST([DPDK_CPPFLAGS])
AC_SUBST([DPDK_LIBS])

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([PLATFORM_IS_LINUX_DPDK],
	       [test "${with_platform}" = "linux-dpdk"])
AC_CONFIG_FILES([platform/linux-dpdk/Makefile
		 platform/linux-dpdk/libodp-dpdk.pc
		 platform/linux-dpdk/include/odp/api/plat/static_inline.h
		 platform/linux-dpdk/test/Makefile
		 platform/linux-dpdk/test/validation/api/pktio/Makefile])
])
