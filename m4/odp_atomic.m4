# ODP_ATOMIC
# ----------
# Run different atomic-related checks
AC_DEFUN([ODP_ATOMIC], [dnl
ODP_ATOMIC_BUILTINS

dnl Check whether -latomic is needed
use_libatomic=no

ODP_ATOMIC_NEEDED_64BIT([use_libatomic=yes])
AC_CHECK_TYPE([__int128], [ODP_ATOMIC_NEEDED_128BIT([use_libatomic=yes])])

if test "x$use_libatomic" = "xyes"; then
  ATOMIC_LIBS="-latomic"
fi
AC_SUBST([ATOMIC_LIBS])
]) # ODP_ATOMIC

# ODP_ATOMIC_BUILTINS
# -------------------
#
AC_DEFUN([ODP_ATOMIC_BUILTINS], [dnl
AC_CACHE_CHECK([for GCC atomic builtins], [odp_cv_atomic_builtins], [dnl
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
    [odp_cv_atomic_builtins=yes],
    [odp_cv_atomic_builtins=no])])

if test "x$odp_cv_atomic_builtins" != "xyes" ; then
    AC_MSG_FAILURE([GCC-style __atomic builtins not supported by the compiler, use gcc > 4.7.0])
fi
]) # ODP_ATOMIC_BUILTINS

# ODP_ATOMIC_NEEDED_64BIT([ACTION_IF_NEEDED])
# -------------------------------------------
#
AC_DEFUN([ODP_ATOMIC_NEEDED_64BIT], [dnl
AC_CACHE_CHECK([whether -latomic is needed for 64-bit atomic built-ins],
	       [odp_cv_atomic_needed_64bit], [dnl
AC_LINK_IFELSE(
  [AC_LANG_SOURCE([[
    #include <stdint.h>
    static uint64_t loc;
    int main(void)
    {
        uint64_t prev = __atomic_exchange_n(&loc, 7, __ATOMIC_RELAXED);
        return 0;
    }
    ]])],
  [odp_cv_atomic_needed_64bit=no],
  [odp_cv_atomic_needed_64bit=yes])])

if test "x$odp_cv_atomic_needed_64bit" = "xyes" ; then
   AC_CHECK_LIB(
     [atomic], [__atomic_exchange_8],
     [m4_default([$1], [:])],
     [AC_MSG_FAILURE([__atomic_exchange_8 is not available])])
fi
]) # ODP_ATOMIC_NEEDED_64BIT

# ODP_ATOMIC_NEEDED_128BIT([ACTION_IF_NEEDED])
# -------------------------------------------
#
AC_DEFUN([ODP_ATOMIC_NEEDED_128BIT], [dnl
AC_CACHE_CHECK([whether -latomic is needed for 128-bit atomic built-ins],
	       [odp_cv_atomic_needed_128bit], [dnl
AC_LINK_IFELSE(
  [AC_LANG_SOURCE([[
    #include <stdint.h>
    static __int128 loc;
    int main(void)
    {
        __int128 prev = __atomic_exchange_n(&loc, 7, __ATOMIC_RELAXED);
        return 0;
    }
    ]])],
  [odp_cv_atomic_needed_128bit=no],
  [odp_cv_atomic_needed_128bit=yes])])

if test "x$odp_cv_atomic_needed_128bit" = "xyes" ; then
   AC_CHECK_LIB(
     [atomic], [__atomic_exchange_16],
     [m4_default([$1], [:])],
     [AC_MSG_FAILURE([__atomic_exchange_16 is not available])])
fi
]) # ODP_ATOMIC_NEEDED_128BIT
