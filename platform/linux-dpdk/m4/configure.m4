AC_MSG_CHECKING(for GCC atomic builtins)
AC_LINK_IFELSE(
    [AC_LANG_SOURCE(
      [[int main() {
        int v = 1;
        __atomic_fetch_add(&v, 1, __ATOMIC_RELAXED);
        __atomic_fetch_sub(&v, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&v, 1, __ATOMIC_RELAXED);
        __atomic_load_n(&v, __ATOMIC_RELAXED);
        return 0;
        }
    ]])],
    AC_MSG_RESULT(yes),
    AC_MSG_RESULT(no)
    echo "GCC-style __atomic builtins not supported by the compiler."
    echo "Use newer version. For gcc > 4.7.0"
    exit -1)

#
# Check that SDK_INSTALL_PATH provided to right dpdk version
#
saved_cflags="$CFLAGS"
CFLAGS="$CFLAGS -I${SDK_INSTALL_PATH}/include"
AC_MSG_CHECKING(for DPDK include files)
AC_LINK_IFELSE(
    [AC_LANG_SOURCE(
      [[
	#include <rte_config.h>
	#include <rte_memory.h>
	#include <rte_eal.h>
	int main() {
        return 0;
        }
    ]])],
    AC_MSG_RESULT(yes),
    AC_MSG_RESULT(no)
    echo "Unable to find DPDK SDK."
    exit -1
	)
CFLAGS="$saved_cflags"
