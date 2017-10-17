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

# ODP_DPDK_CHECK(CPPFLAGS, LDFLAGS, ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
# -----------------------------------------------------------------------
# Check for DPDK availability
AC_DEFUN([ODP_DPDK_CHECK], [dnl
##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_LDFLAGS=$LDFLAGS
OLD_LIBS=$LIBS
OLD_CPPFLAGS=$CPPFLAGS
LDFLAGS="$2 $LDFLAGS"
CPPFLAGS="$1 $CPPFLAGS"

dpdk_check_ok=yes

AC_CHECK_HEADERS([rte_config.h], [],
		 [dpdk_check_ok=no])

AC_CHECK_LIB([dpdk], [rte_eal_init], [],
	     [dpdk_check_ok=no], [-ldl -lpthread -lnuma])
AS_IF([test "x$dpdk_check_ok" != "xno"],
      [m4_default([$3], [:])],
      [m4_default([$4], [:])])

##########################################################################
# Restore old saved variables
##########################################################################
LDFLAGS=$OLD_LDFLAGS
LIBS=$OLD_LIBS
CPPFLAGS=$OLD_CPPFLAGS
])
