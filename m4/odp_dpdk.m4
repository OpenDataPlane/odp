# ODP_DPDK_PMDS(DPDK_DRIVER_PATH)
# -------------------------------
# Update DPDK_LIBS to include dependencies.
AC_DEFUN([ODP_DPDK_PMDS], [dnl
AC_MSG_NOTICE([Looking for DPDK PMDs at $1])
for filename in "$1"/librte_pmd_*.a; do
cur_driver=`basename "$filename" .a | sed -e 's/^lib//'`

# Match pattern is filled to 'filename' once if no matches are found
AS_IF([test "x$cur_driver" = "xrte_pmd_*"], [break])

AS_CASE([$cur_driver],
    [rte_pmd_nfp], [AS_VAR_APPEND([DPDK_LIBS], [" -lm"])],
    [rte_pmd_mlx4], [AS_VAR_APPEND([DPDK_LIBS], [" -lmlx4 -libverbs"])],
    [rte_pmd_mlx5], [AS_VAR_APPEND([DPDK_LIBS], [" -lmlx5 -libverbs -lmnl"])],
    [rte_pmd_pcap], [AS_VAR_APPEND([DPDK_LIBS], [" -lpcap"])],
    [rte_pmd_aesni_gcm], [AS_VAR_APPEND([DPDK_LIBS], [" -lIPSec_MB"])],
    [rte_pmd_aesni_mb], [AS_VAR_APPEND([DPDK_LIBS], [" -lIPSec_MB"])],
    [rte_pmd_kasumi], [AS_VAR_APPEND([DPDK_LIBS], [" -lsso_kasumi"])],
    [rte_pmd_snow3g], [AS_VAR_APPEND([DPDK_LIBS], [" -lsso_snow3g"])],
    [rte_pmd_zuc], [AS_VAR_APPEND([DPDK_LIBS], [" -lsso_zuc"])],
    [rte_pmd_qat], [AS_VAR_APPEND([DPDK_LIBS], [" -lcrypto"])],
    [rte_pmd_openssl], [AS_VAR_APPEND([DPDK_LIBS], [" -lcrypto"])])
done
])

# _ODP_DPDK_SET_LIBS
# --------------------
# Set DPDK_LIBS/DPDK_LIBS_LT/DPDK_LIBS_LIBODP depending on DPDK setup
AC_DEFUN([_ODP_DPDK_SET_LIBS], [dnl
ODP_DPDK_PMDS([$DPDK_PMD_PATH])
DPDK_LIB="-Wl,--whole-archive,-ldpdk,--no-whole-archive"
AS_IF([test "x$DPDK_SHARED" = "xyes"], [dnl
    # applications don't need to be linked to anything, just rpath
    DPDK_LIBS_LT="$DPDK_RPATH_LT"
    # static linking flags will need -ldpdk
    DPDK_LIBS_LT_STATIC="$DPDK_LDFLAGS $DPDK_LIB $DPDK_LIBS"
    DPDK_LIBS="-Wl,--no-as-needed,-ldpdk,--as-needed,`echo $DPDK_LIBS | sed -e 's/ /,/g'`"
    DPDK_LIBS="$DPDK_LDFLAGS $DPDK_RPATH $DPDK_LIBS"
    # link libodp-linux with -ldpdk
    DPDK_LIBS_LIBODP="$DPDK_LIBS"
], [dnl
    # build long list of libraries for applications, which should not be
    # rearranged by libtool
    DPDK_LIBS_LT="`echo $DPDK_LIBS | sed -e 's/^/-Wc,/' -e 's/ /,/g'`"
    DPDK_LIBS_LT="$DPDK_LDFLAGS $DPDK_LIB $DPDK_LIBS_LT $DPDK_LIBS"
    DPDK_LIBS_LT_STATIC="$DPDK_LIBS_LT"
    # static linking flags follow the suite
    DPDK_LIBS="$DPDK_LDFLAGS $DPDK_LIB $DPDK_LIBS"
    # link libodp-linux with libtool linking flags
    DPDK_LIBS_LIBODP="$DPDK_LIBS_LT"
])

OLD_LIBS=$LIBS
LIBS="-lnuma"
AC_TRY_LINK_FUNC([numa_num_configured_nodes],
		 [AC_DEFINE([_ODP_HAVE_NUMA_LIBRARY], [1],
			    [Define to 1 if numa library is usable])
		 AS_VAR_APPEND([DPDK_LIBS_LIBODP], [" -lnuma"])])
LIBS=$OLD_LIBS

AC_SUBST([DPDK_LIBS])
AC_SUBST([DPDK_LIBS_LIBODP])
AC_SUBST([DPDK_LIBS_LT])
AC_SUBST([DPDK_LIBS_LT_STATIC])
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
	        DPDK_LIBS="$2"],
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
       AC_SUBST([DPDK_CFLAGS])
       $3],
      [$4])

##########################################################################
# Restore old saved variables
##########################################################################
CPPFLAGS=$OLD_CPPFLAGS
])

# _ODP_DPDK_LEGACY_SYSTEM(ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
# ------------------------------------------------------------------------
# Locate DPDK installation
AC_DEFUN([_ODP_DPDK_LEGACY_SYSTEM], [dnl
    DPDK_CFLAGS="-isystem /usr/include/dpdk"
    DPDK_LDFLAGS=""
    DPDK_LIB_PATH="`$CC $CFLAGS $LDFLAGS --print-file-name=libdpdk.so`"
    if test "$DPDK_LIB_PATH" = "libdpdk.so" ; then
	DPDK_LIB_PATH="`$CC $CFLAGS $LDFLAGS --print-file-name=libdpdk.a`"
        AS_IF([test "$DPDK_LIB_PATH" = "libdpdk.a"],
           [AC_MSG_FAILURE([Could not locate system DPDK library directory])])
    else
	DPDK_SHARED=yes
    fi
    DPDK_LIB_PATH=`AS_DIRNAME(["$DPDK_LIB_PATH"])`
    DPDK_PMD_PATH="$DPDK_LIB_PATH"
    AS_IF([test "x$DPDK_SHARED" = "xyes"],
	    [AC_MSG_NOTICE([Using shared DPDK library found at $DPDK_LIB_PATH])],
	    [AC_MSG_NOTICE([Using static DPDK library found at $DPDK_LIB_PATH])])
    _ODP_DPDK_CHECK([$DPDK_CFLAGS], [$DPDK_LDFLAGS], [$1], [$2])
    DPDK_PKG=""
    AC_SUBST([DPDK_PKG])
])

# _ODP_DPDK_LEGACY(PATH, ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
# ------------------------------------------------------------------------
# Locate DPDK installation
AC_DEFUN([_ODP_DPDK_LEGACY], [dnl
    DPDK_CFLAGS="-isystem $1/include/dpdk"
    DPDK_LIB_PATH="$1/lib"
    DPDK_LDFLAGS="-L$DPDK_LIB_PATH"
    AS_IF([test -r "$DPDK_LIB_PATH"/libdpdk.so], [dnl
	DPDK_RPATH="-Wl,-rpath,$DPDK_LIB_PATH"
	DPDK_RPATH_LT="-R$DPDK_LIB_PATH"
	DPDK_SHARED=yes],
	[test ! -r "$DPDK_LIB_PATH"/libdpdk.a], [dnl
        AC_MSG_FAILURE([Could not find DPDK])])
    DPDK_PMD_PATH="$DPDK_LIB_PATH"
    AS_IF([test "x$DPDK_SHARED" = "xyes"],
	    [AC_MSG_NOTICE([Using shared DPDK library found at $DPDK_LIB_PATH])],
	    [AC_MSG_NOTICE([Using static DPDK library found at $DPDK_LIB_PATH])])
    _ODP_DPDK_CHECK([$DPDK_CFLAGS], [$DPDK_LDFLAGS], [$2], [$3])
    DPDK_PKG=""
    AC_SUBST([DPDK_PKG])
])

m4_ifndef([PKG_CHECK_MODULES_STATIC],
[m4_define([PKG_CHECK_MODULES_STATIC],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
_save_PKG_CONFIG=$PKG_CONFIG
PKG_CONFIG="$PKG_CONFIG --static"
PKG_CHECK_MODULES($@)
PKG_CONFIG=$_save_PKG_CONFIG[]dnl
])])dnl PKG_CHECK_MODULES_STATIC

# _ODP_DPDK_PKGCONFIG
# -----------------------------------------------------------------------
# Configure DPDK using pkg-config information
AC_DEFUN([_ODP_DPDK_PKGCONFIG], [dnl
PKG_CHECK_MODULES_STATIC([DPDK_STATIC], [libdpdk])
DPDK_PKG=", libdpdk"
AC_SUBST([DPDK_PKG])
# applications don't need to be linked to anything, just rpath
DPDK_LIBS_LT=""
# compile all static flags into single argument to fool libtool
DPDK_LIBS_LT_STATIC="-pthread -Wl,`echo $DPDK_STATIC_LIBS | sed -e 's/-pthread//g' -e 's/ \+/,/g' -e 's/-Wl,//g'`"
# FIXME: this might need to be changed to DPDK_LIBS_STATIC
DPDK_LIBS_LIBODP="$DPDK_LIBS"
DPDK_LIBS=""
])

# ODP_DPDK(DPDK_PATH, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# -----------------------------------------------------------------------
# Check for DPDK availability
AC_DEFUN([ODP_DPDK], [dnl
AS_IF([test "x$1" = "xsystem"],
      [PKG_CHECK_MODULES([DPDK], [libdpdk],
			 [AC_MSG_NOTICE([Using DPDK detected via pkg-config])
			 _ODP_DPDK_PKGCONFIG
			 m4_default([$2], [:])],
			 [_ODP_DPDK_LEGACY_SYSTEM([m4_default([$2], [:])],
						  [m4_default([$3], [:])])])],
      [_ODP_DPDK_LEGACY($1, [m4_default([$2], [:])], [m4_default([$3], [:])])]
      )])
