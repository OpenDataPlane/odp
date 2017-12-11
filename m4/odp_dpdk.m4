# ODP_DPDK_PMDS(DPDK_DRIVER_PATH)
# -------------------------------
# Build a list of DPDK PMD drivers in DPDK_PMDS variable
AC_DEFUN([ODP_DPDK_PMDS], [dnl
AS_VAR_SET([DPDK_PMDS], [-Wl,--whole-archive,])
for filename in "$1"/librte_pmd_*.a; do
cur_driver=`basename "$filename" .a | sed -e 's/^lib//'`
# rte_pmd_nfp has external dependencies which break linking
if test "$cur_driver" = "rte_pmd_nfp"; then
    echo "skip linking rte_pmd_nfp"
else
    AS_VAR_APPEND([DPDK_PMDS], [-l$cur_driver,])
fi
done
AS_VAR_APPEND([DPDK_PMDS], [--no-whole-archive])
AC_SUBST([DPDK_PMDS])
])

# _ODP_DPDK_CHECK_LIB(LDFLAGS, [LIBS], [EXTRA_LIBS])
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
	        DPDK_LIBS="$1 -ldpdk $3 $2"],
	       [AC_MSG_RESULT([no])])

##########################################################################
# Restore old saved variables
##########################################################################
LDFLAGS=$OLD_LDFLAGS
LIBS=$OLD_LIBS
])

# ODP_DPDK_CHECK(CPPFLAGS, LDFLAGS, ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
# -----------------------------------------------------------------------
# Check for DPDK availability
AC_DEFUN([ODP_DPDK_CHECK], [dnl
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
      [_ODP_DPDK_CHECK_LIB([$2], [-ldl -lpthread], [-lm])])
AS_IF([test "x$DPDK_LIBS" = "x"],
      [_ODP_DPDK_CHECK_LIB([$2], [-ldl -lpthread -lnuma], [-lm])])
AS_IF([test "x$DPDK_LIBS" = "x"],
      [dpdk_check_ok=no])
AS_IF([test "x$dpdk_check_ok" != "xno"],
      [AC_SUBST([DPDK_LIBS])
       m4_default([$3], [:])],
      [m4_default([$4], [:])])

##########################################################################
# Restore old saved variables
##########################################################################
CPPFLAGS=$OLD_CPPFLAGS
])
