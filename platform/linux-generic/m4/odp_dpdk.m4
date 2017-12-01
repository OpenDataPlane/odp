##########################################################################
# Enable DPDK support
##########################################################################
pktio_dpdk_support=no

AC_ARG_ENABLE([dpdk],
	      [AS_HELP_STRING([--enable-dpdk], [enable DPDK support for Packet I/O])],
	      [pktio_dpdk_support=$enableval
	       DPDK_PATH=system])

AC_ARG_WITH([dpdk-path],
[AS_HELP_STRING([--with-dpdk-path=DIR], [path to dpdk build directory])],
    [DPDK_PATH="$withval"
     pktio_dpdk_support=yes],[])

AS_IF([test "x$DPDK_PATH" = "xsystem"],
      [DPDK_CPPFLAGS="-isystem/usr/include/dpdk"
       DPDK_LDFLAGS=""
       DPDK_PMD_PATH="`$CC --print-file-name=librte_pmd_null.a`"
       DPDK_PMD_PATH="`dirname "$DPDK_PMD_PATH"`"
       AS_IF([test "x$DPDK_PMD_PATH" = "x"],
	     [AC_MSG_FAILURE([Could not locate system DPDK PMD directory])])],
      [DPDK_CPPFLAGS="-isystem $DPDK_PATH/include"
       DPDK_LDFLAGS="-L$DPDK_PATH/lib"
       DPDK_PMD_PATH="$DPDK_PATH/lib"])

##########################################################################
# Enable zero-copy DPDK pktio
##########################################################################
zero_copy=0
AC_ARG_ENABLE([dpdk-zero-copy],
    [AS_HELP_STRING([--enable-dpdk-zero-copy], [enable experimental zero-copy DPDK pktio mode])],
    [if test x$enableval = xyes; then
        zero_copy=1
    fi])

##########################################################################
# Check for DPDK availability
#
# DPDK pmd drivers are not linked unless the --whole-archive option is
# used. No spaces are allowed between the --whole-arhive flags.
##########################################################################
if test x$pktio_dpdk_support = xyes
then
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
    AC_SUBST([DPDK_CPPFLAGS])
    AC_SUBST([DPDK_LIBS])
else
    pktio_dpdk_support=no
fi

AM_CONDITIONAL([PKTIO_DPDK], [test x$pktio_dpdk_support = xyes ])
