##########################################################################
# Enable DPDK support
##########################################################################
pktio_dpdk_support=no
AC_ARG_WITH([dpdk-path],
AC_HELP_STRING([--with-dpdk-path=DIR   path to dpdk build directory]),
    [DPDK_PATH="$withval"
    DPDK_CPPFLAGS="-msse4.2 -isystem $DPDK_PATH/include"
    pktio_dpdk_support=yes],[])

##########################################################################
# Enable zero-copy DPDK pktio
##########################################################################
zero_copy=0
AC_ARG_ENABLE([dpdk-zero-copy],
    [  --enable-dpdk-zero-copy  enable experimental zero-copy DPDK pktio mode],
    [if test x$enableval = xyes; then
        zero_copy=1
    fi])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$DPDK_CPPFLAGS $CPPFLAGS"

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

    AS_VAR_SET([DPDK_PMDS], [-Wl,--whole-archive,])
    for filename in "$DPDK_PATH"/lib/librte_pmd_*.a; do
        cur_driver=`basename "$filename" .a | sed -e 's/^lib//'`
        # rte_pmd_nfp has external dependencies which break linking
        if test "$cur_driver" = "rte_pmd_nfp"; then
            echo "skip linking rte_pmd_nfp"
        else
            AS_VAR_APPEND([DPDK_PMDS], [-l$cur_driver,])
        fi
    done
    AS_VAR_APPEND([DPDK_PMDS], [--no-whole-archive])

    ODP_CFLAGS="$ODP_CFLAGS -DODP_PKTIO_DPDK -DODP_DPDK_ZERO_COPY=$zero_copy"
    DPDK_LIBS="-L$DPDK_PATH/lib -ldpdk -lpthread -ldl -lpcap -lm"
    AC_SUBST([DPDK_CPPFLAGS])
    AC_SUBST([DPDK_LIBS])
    AC_SUBST([DPDK_PMDS])
else
    pktio_dpdk_support=no
fi

##########################################################################
# Restore old saved variables
##########################################################################
CPPFLAGS=$OLD_CPPFLAGS

AM_CONDITIONAL([PKTIO_DPDK], [test x$pktio_dpdk_support = xyes ])
