# Enable -fvisibility=hidden if using a gcc that supports it
OLD_CFLAGS="$CFLAGS"
AC_MSG_CHECKING([whether $CC supports -fvisibility=hidden])
VISIBILITY_CFLAGS="-fvisibility=hidden"
CFLAGS="$CFLAGS $VISIBILITY_CFLAGS"
AC_LINK_IFELSE([AC_LANG_PROGRAM()], AC_MSG_RESULT([yes]),
       [VISIBILITY_CFLAGS=""; AC_MSG_RESULT([no])]);

AC_SUBST(VISIBILITY_CFLAGS)
# Restore CFLAGS; VISIBILITY_CFLAGS are added to it where needed.
CFLAGS=$OLD_CFLAGS

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

dnl Check for libconfig (required)
PKG_CHECK_MODULES([LIBCONFIG], [libconfig >= 1.3.2])

dnl Check whether -latomic is needed
use_libatomic=no

AC_MSG_CHECKING(whether -latomic is needed for 64-bit atomic built-ins)
AC_LINK_IFELSE(
  [AC_LANG_SOURCE([[
    static int loc;
    int main(void)
    {
        int prev = __atomic_exchange_n(&loc, 7, __ATOMIC_RELAXED);
        return 0;
    }
    ]])],
  [AC_MSG_RESULT(no)],
  [AC_MSG_RESULT(yes)
   AC_CHECK_LIB(
     [atomic], [__atomic_exchange_8],
     [use_libatomic=yes],
     [AC_MSG_CHECKING([__atomic_exchange_8 is not available])])
  ])

AC_MSG_CHECKING(whether -latomic is needed for 128-bit atomic built-ins)
AC_LINK_IFELSE(
  [AC_LANG_SOURCE([[
    static __int128 loc;
    int main(void)
    {
        __int128 prev;
        prev = __atomic_exchange_n(&loc, 7, __ATOMIC_RELAXED);
        return 0;
    }
    ]])],
  [AC_MSG_RESULT(no)],
  [AC_MSG_RESULT(yes)
   AC_CHECK_LIB(
     [atomic], [__atomic_exchange_16],
     [use_libatomic=yes],
     [AC_MSG_CHECKING([cannot detect support for 128-bit atomics])])
  ])

if test "x$use_libatomic" = "xyes"; then
  ATOMIC_LIBS="-latomic"
fi
AC_SUBST([ATOMIC_LIBS])

# linux-generic PCAP support is not relevant as the code doesn't use
# linux-generic pktio at all. And DPDK has its own PCAP support anyway
AM_CONDITIONAL([HAVE_PCAP], [false])
AM_CONDITIONAL([netmap_support], [false])
AM_CONDITIONAL([PKTIO_DPDK], [false])
m4_include([platform/linux-dpdk/m4/odp_pthread.m4])
ODP_TIMER
ODP_OPENSSL
m4_include([platform/linux-dpdk/m4/odp_modules.m4])
m4_include([platform/linux-dpdk/m4/odp_schedule.m4])

m4_include([platform/linux-dpdk/m4/performance.m4])

##########################################################################
# DPDK build variables
##########################################################################
DPDK_DRIVER_DIR=/usr/lib/$(uname -m)-linux-gnu
AS_CASE($host_cpu, [x86_64], [DPDK_CPPFLAGS="$DPDK_CPPFLAGS -msse4.2"])
if test "x${SDK_INSTALL_PATH}" = "x"; then
    DPDK_CPPFLAGS="$DPDK_CPPFLAGS -I/usr/include/dpdk"
else
    DPDK_DRIVER_DIR=$SDK_INSTALL_PATH/lib
    DPDK_CPPFLAGS="$DPDK_CPPFLAGS -I$SDK_INSTALL_PATH/include"
    DPDK_LDFLAGS="$DPDK_CPPFLAGS -L$SDK_INSTALL_PATH/lib"
fi

# Check if we should link against the static or dynamic DPDK library
AC_ARG_ENABLE([shared-dpdk],
	[  --enable-shared-dpdk    link against the shared DPDK library],
	[if test "x$enableval" = "xyes"; then
		shared_dpdk=true
	fi])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_LDFLAGS=$LDFLAGS
OLD_CPPFLAGS=$CPPFLAGS
LDFLAGS="$DPDK_LDFLAGS $LDFLAGS"
CPPFLAGS="$DPDK_CPPFLAGS $CPPFLAGS -pthread"

##########################################################################
# Check for DPDK availability
##########################################################################
AC_CHECK_HEADERS([rte_config.h], [],
    [AC_MSG_FAILURE(["can't find DPDK headers"])])

##########################################################################
# In case of static linking DPDK pmd drivers are not linked unless the
# --whole-archive option is used. No spaces are allowed between the
# --whole-arhive flags.
##########################################################################
if test "x$shared_dpdk" = "xtrue"; then
    DPDK_LIBS="-Wl,--no-as-needed,-ldpdk,-as-needed -ldl -lm -lpcap"
else

    AS_VAR_SET([DPDK_PMDS], [-Wl,--whole-archive,])
    for filename in $DPDK_DRIVER_DIR/librte_pmd_*.a; do
        cur_driver=`basename "$filename" .a | sed -e 's/^lib//'`
        # rte_pmd_nfp has external dependencies which break linking
        if test "$cur_driver" = "rte_pmd_nfp"; then
            echo "skip linking rte_pmd_nfp"
        else
            AS_VAR_APPEND([DPDK_PMDS], [-l$cur_driver,])
        fi
    done
    AS_VAR_APPEND([DPDK_PMDS], [--no-whole-archive])

    DPDK_LIBS="-L$DPDK_DRIVER_DIR -ldpdk -lpthread -ldl -lm -lpcap"
    AC_SUBST([DPDK_PMDS])
fi

##########################################################################
# Restore old saved variables
##########################################################################
LDFLAGS=$OLD_LDFLAGS
CPPFLAGS=$OLD_CPPFLAGS

AC_SUBST([DPDK_CPPFLAGS])
AC_SUBST([DPDK_LDFLAGS])
AC_SUBST([DPDK_LIBS])

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([PLATFORM_IS_LINUX_DPDK],
               [test "${with_platform}" = "linux-dpdk"])
])

AC_CONFIG_FILES([platform/linux-dpdk/Makefile
		 platform/linux-dpdk/libodp-dpdk.pc
		 platform/linux-dpdk/include/odp/api/plat/static_inline.h
		 platform/linux-dpdk/test/Makefile
		 platform/linux-dpdk/test/validation/api/pktio/Makefile])

##########################################################################
# Enable dpdk pktio build
##########################################################################
AC_DEFINE([ODP_PKTIO_DPDK], [1],
	      [Define to 1 to enable DPDK packet I/O support])
