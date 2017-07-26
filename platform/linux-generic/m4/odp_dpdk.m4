##########################################################################
# Enable DPDK support
##########################################################################
pktio_dpdk_support=no
AC_ARG_WITH([dpdk-path],
AC_HELP_STRING([--with-dpdk-path=DIR   path to dpdk build directory]),
    [DPDK_PATH=$withval
    AM_CPPFLAGS="$AM_CPPFLAGS -msse4.2 -isystem $DPDK_PATH/include"
    pktio_dpdk_support=yes],[])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$AM_CPPFLAGS $CPPFLAGS"

##########################################################################
# Check for DPDK availability
#
# DPDK pmd drivers are not linked unless the --whole-archive option is
# used. No spaces are allowed between the --whole-arhive flags.
##########################################################################
if test x$pktio_dpdk_support = xyes
then
    AC_CHECK_HEADERS([rte_config.h], [],
        [AC_MSG_FAILURE(["can't find DPDK header"])])

    DPDK_PMD=--whole-archive,
    for filename in $with_dpdk_path/lib/*.a; do
        cur_driver=`echo $(basename "$filename" .a) | \
            sed -n 's/^\(librte_pmd_\)/-lrte_pmd_/p' | sed -n 's/$/,/p'`
        # rte_pmd_nfp has external dependencies which break linking
        if test "$cur_driver" = "-lrte_pmd_nfp,"; then
            echo "skip linking rte_pmd_nfp"
        else
            DPDK_PMD+=$cur_driver
        fi
    done
    DPDK_PMD+=--no-whole-archive

    ODP_CFLAGS="$ODP_CFLAGS -DODP_PKTIO_DPDK"
    AM_LDFLAGS="$AM_LDFLAGS -L$DPDK_PATH/lib -Wl,$DPDK_PMD"
    LIBS="$LIBS -ldpdk -ldl -lpcap"
else
    pktio_dpdk_support=no
fi

##########################################################################
# Restore old saved variables
##########################################################################
CPPFLAGS=$OLD_CPPFLAGS
