##########################################################################
# Enable DPDK support
##########################################################################
pktio_dpdk_support=no
AC_ARG_ENABLE([dpdk_support],
    [  --enable-dpdk-support  include dpdk IO support],
    [if test x$enableval = xyes; then
        pktio_dpdk_support=yes
    fi])

##########################################################################
# Set optional DPDK path
##########################################################################
AC_ARG_WITH([dpdk-path],
AC_HELP_STRING([--with-dpdk-path=DIR   path to dpdk build directory],
               [(or in the default path if not specified).]),
    [DPDK_PATH=$withval
    AM_CPPFLAGS="$AM_CPPFLAGS -msse4.2 -isystem $DPDK_PATH/include"
    AM_LDFLAGS="$AM_LDFLAGS -L$DPDK_PATH/lib"
    LIBS="$LIBS -ldpdk -ldl -lpcap"
    pktio_dpdk_support=yes],[])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$AM_CPPFLAGS $CPPFLAGS"

##########################################################################
# Check for DPDK availability
##########################################################################
if test x$pktio_dpdk_support = xyes
then
    AC_CHECK_HEADERS([rte_config.h], [],
        [AC_MSG_FAILURE(["can't find DPDK header"])])
    ODP_CFLAGS="$ODP_CFLAGS -DODP_PKTIO_DPDK"
else
    pktio_dpdk_support=no
fi

##########################################################################
# Restore old saved variables
##########################################################################
CPPFLAGS=$OLD_CPPFLAGS
