# ODP_DPDK_PMDS(DPDK_DRIVER_PATH)
# -------------------------------
# Build a list of DPDK PMD drivers in DPDK_PMDS variable.
# Updated DPDK_LIBS to include dependencies.
AC_DEFUN([ODP_DPDK_PMDS], [dnl
AS_VAR_SET([DPDK_PMDS], ["-Wl,--whole-archive,"])
for filename in "$1"/librte_pmd_*.a; do
cur_driver=`basename "$filename" .a | sed -e 's/^lib//'`
AS_VAR_APPEND([DPDK_PMDS], [-l$cur_driver,])
AS_CASE([$cur_driver],
    [rte_pmd_nfp], [AS_VAR_APPEND([DPDK_LIBS], [" -lm"])],
    [rte_pmd_mlx4], [AS_VAR_APPEND([DPDK_LIBS], [" -lmlx4 -libverbs"])],
    [rte_pmd_mlx5], [AS_VAR_APPEND([DPDK_LIBS], [" -lmlx5 -libverbs"])],
    [rte_pmd_pcap], [AS_VAR_APPEND([DPDK_LIBS], [" -lpcap"])],
    [rte_pmd_openssl], [AS_VAR_APPEND([DPDK_LIBS], [" -lcrypto"])])
done
AS_VAR_APPEND([DPDK_PMDS], [--no-whole-archive])
])

# _ODP_DPDK_SET_LIBS
# --------------------
# Set DPDK_LIBS/DPDK_LIBS_LT/DPDK_LIBS_LIBODP depending on DPDK setup
AC_DEFUN([_ODP_DPDK_SET_LIBS], [dnl
AS_IF([test "x$DPDK_SHARED" = "xyes"], [dnl
    # applications don't need to be linked to anything, just rpath
    DPDK_LIBS_LT="$DPDK_RPATH_LT"
    # static linking flags will need -ldpdk
    DPDK_LIBS="-Wl,--no-as-needed,-ldpdk,--as-needed,`echo $DPDK_LIBS | sed -e 's/ /,/g'`"
    DPDK_LIBS="$DPDK_LDFLAGS $DPDK_RPATH $DPDK_LIBS"
    # link libodp-linux with -ldpdk
    DPDK_LIBS_LIBODP="$DPDK_LIBS"
], [dnl
    ODP_DPDK_PMDS([$DPDK_PMD_PATH])
    # build long list of libraries for applications, which should not be
    # rearranged by libtool
    DPDK_LIBS_LT="`echo $DPDK_LIBS | sed -e 's/^/-Wc,/' -e 's/ /,/g'`"
    DPDK_LIBS_LT="$DPDK_LDFLAGS $DPDK_PMDS $DPDK_LIBS_LT $DPDK_LIBS"
    # static linking flags follow the suite
    DPDK_LIBS="$DPDK_LDFLAGS $DPDK_PMDS $DPDK_LIBS"
    # link libodp-linux with libtool linking flags
    DPDK_LIBS_LIBODP="$DPDK_LIBS_LT"
])
AC_SUBST([DPDK_LIBS])
AC_SUBST([DPDK_LIBS_LIBODP])
AC_SUBST([DPDK_LIBS_LT])
])

# _ODP_DPDK_CHECK_LIB(LDFLAGS, [LIBS])
# ----------------------------------
# Check if one can use -ldpdk with provided set of libs
AC_DEFUN([_ODP_DPDK_CHECK_LIB], [dnl
##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_LDFLAGS=$LDFLAGS
OLD_LIBS=$LIBS
LDFLAGS="$1 $LDFLAGS"
LIBS="$LIBS -ldpdk $2"

AC_MSG_CHECKING([for rte_eal_init in -ldpdk $2])
AC_LINK_IFELSE([AC_LANG_CALL([], [rte_eal_init])],
	       [AC_MSG_RESULT([yes])
	        DPDK_LIBS="-ldpdk $2"],
	       [AC_MSG_RESULT([no])])

##########################################################################
# Restore old saved variables
##########################################################################
LDFLAGS=$OLD_LDFLAGS
LIBS=$OLD_LIBS
])

# _ODP_DPDK_CHECK(CPPFLAGS, LDFLAGS, ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
# ------------------------------------------------------------------------
# Check for DPDK availability
AC_DEFUN([_ODP_DPDK_CHECK], [dnl
##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$1 $CPPFLAGS"

dpdk_check_ok=yes

AC_CHECK_HEADERS([rte_config.h], [],
		 [dpdk_check_ok=no])

DPDK_LIBS=""
_ODP_DPDK_CHECK_LIB([$2])
AS_IF([test "x$DPDK_LIBS" = "x"],
      [_ODP_DPDK_CHECK_LIB([$2], [-ldl -lpthread])])
AS_IF([test "x$DPDK_LIBS" = "x"],
      [_ODP_DPDK_CHECK_LIB([$2], [-ldl -lpthread -lnuma])])
AS_IF([test "x$DPDK_LIBS" = "x"],
      [dpdk_check_ok=no])
AS_IF([test "x$dpdk_check_ok" != "xno"],
      [_ODP_DPDK_SET_LIBS
       AC_SUBST([DPDK_CPPFLAGS])
       m4_default([$3], [:])],
      [m4_default([$4], [:])])

##########################################################################
# Restore old saved variables
##########################################################################
CPPFLAGS=$OLD_CPPFLAGS
])

# ODP_DPDK(DPDK_PATH, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# -----------------------------------------------------------------------
# Check for DPDK availability
AC_DEFUN([ODP_DPDK], [dnl
AS_IF([test "x$1" = "xsystem"], [dnl
    DPDK_CPPFLAGS="-isystem /usr/include/dpdk"
    DPDK_LDFLAGS=""
    DPDK_LIB_PATH="`$CC --print-file-name=libdpdk.so`"
    if test "$DPDK_LIB_PATH" = "libdpdk.so" ; then
	DPDK_LIB_PATH="`$CC --print-file-name=libdpdk.a`"
        AS_IF([test "$DPDK_LIB_PATH" = "libdpdk.a"],
           [AC_MSG_FAILURE([Could not locate system DPDK library directory])])
    else
	DPDK_SHARED=yes
    fi
    DPDK_LIB_PATH=`AS_DIRNAME(["$DPDK_LIB_PATH"])`
], [dnl
    DPDK_CPPFLAGS="-isystem $1/include/dpdk"
    DPDK_LIB_PATH="$1/lib"
    DPDK_LDFLAGS="-L$DPDK_LIB_PATH"
    if test -r "$DPDK_LIB_PATH"/libdpdk.so ; then
	DPDK_RPATH="-Wl,-rpath,$DPDK_LIB_PATH"
	DPDK_RPATH_LT="-R$DPDK_LIB_PATH"
	DPDK_SHARED=yes
    elif test ! -r "$DPDK_LIB_PATH"/libdpdk.a ; then
        AC_MSG_FAILURE([Could not find DPDK])
    fi
])
DPDK_PMD_PATH="$DPDK_LIB_PATH"
AS_IF([test "x$DPDK_SHARED" = "xyes"],
      [AC_MSG_NOTICE([Using shared DPDK library found at $DPDK_LIB_PATH])],
      [AC_MSG_NOTICE([Using static DPDK library found at $DPDK_LIB_PATH])])
_ODP_DPDK_CHECK([$DPDK_CPPFLAGS], [$DPDK_LDFLAGS], [$2], [$3])
])
