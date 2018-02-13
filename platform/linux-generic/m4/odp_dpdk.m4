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
    ODP_DPDK([$DPDK_PATH], [],
	     [AC_MSG_FAILURE([can't find DPDK])])

    AC_DEFINE([ODP_PKTIO_DPDK], [1],
	      [Define to 1 to enable DPDK packet I/O support])
    AC_DEFINE_UNQUOTED([ODP_DPDK_ZERO_COPY], [$zero_copy],
	      [Define to 1 to enable DPDK zero copy support])
else
    pktio_dpdk_support=no
fi

AM_CONDITIONAL([PKTIO_DPDK], [test x$pktio_dpdk_support = xyes ])
