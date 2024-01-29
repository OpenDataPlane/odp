# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2017 Linaro Limited
#

# ODP_DPDK (DPDK_SHARED, ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
# -----------------------------------------------------------------------
# Configure DPDK using pkg-config information
AC_DEFUN([ODP_DPDK], [dnl
dpdk_shared="$1"
if test "x$dpdk_shared" = "xyes" ; then
    PKG_CHECK_MODULES([DPDK], [libdpdk],
                      [AC_MSG_NOTICE([Using shared DPDK lib])
                       m4_default([$2], [:])], [m4_default([$3], [:])])
else
    PKG_CHECK_MODULES_STATIC([DPDK], [libdpdk],
                             [AC_MSG_NOTICE([Using static DPDK lib])
                              m4_default([$2], [:])], [m4_default([$3], [:])])
fi
if test "x$dpdk_shared" = "xyes"; then
    DPDK_LIBS_LIBODP="$DPDK_LIBS"
    DPDK_LIBS_LT="$DPDK_LIBS"
    # Set RPATH if library path is found
    DPDK_LIB_PATH=$(echo "$DPDK_LIBS" | grep -o -- '-L\S*' | sed 's/^-L//')
    if test -n "$DPDK_LIB_PATH"; then
        DPDK_LIBS_LIBODP+=" -Wl,-rpath,$DPDK_LIB_PATH"
        # Debian / Ubuntu has relatively recently made new-dtags the
        # default, while others (e.g. Fedora) have not changed it. RPATH
        # is extended recursively when resolving transitive dependencies,
        # while RUNPATH (new-dtags) is not. We use RPATH to point to rte
        # libraries so that they can be found when PMDs are loaded in
        # rte_eal_init(). So we need to explicitly disable new-dtags.
        DPDK_LIBS_LT+=" -Wl,--disable-new-dtags -R$DPDK_LIB_PATH"
    fi
else
    # Build a list of libraries, which should not be rearranged by libtool.
    # This ensures that DPDK constructors are included properly.
    DPDK_LIBS_LIBODP=$(echo "$DPDK_LIBS" | sed -e 's/\ *$//g' -e 's/ /,/g' -e 's/-Wl,//g')
    DPDK_LIBS_LIBODP=$(echo "$DPDK_LIBS_LIBODP" | sed 's/-pthread/-lpthread/g')
    DPDK_LIBS_LIBODP="-Wl,$DPDK_LIBS_LIBODP"
    DPDK_LIBS_LT="$DPDK_LIBS_LIBODP"
fi

DPDK_LIBS=$DPDK_LIBS_LIBODP

AC_SUBST([DPDK_LIBS])
AC_SUBST([DPDK_LIBS_LT])
])
