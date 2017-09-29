##########################################################################
# Enable/disable Unit tests
##########################################################################
AC_ARG_ENABLE([test_vald],
    [AS_HELP_STRING([--enable-test-vald], [run test in test/validation])],
    [test_vald=$enableval],
    [test_vald=check])

##########################################################################
# Check for CUnit availability
##########################################################################
cunit_support=$test_vald
AS_IF([test "x$cunit_support" != "xno"],
      [PKG_CHECK_MODULES([CUNIT], [cunit], [cunit_support=yes],
      [AC_MSG_WARN([pkg-config could not find CUnit, guessing])
    cunit_support=yes
    AC_CHECK_HEADERS([CUnit/Basic.h], [], [cunit_support=no])
    AC_CHECK_LIB([cunit], [CU_get_error], [CUNIT_LIBS="-lcunit"],
		 [cunit_support=no])
])])

AS_IF([test "x$test_vald" = "xyes" -a "x$cunit_support" = "xno"],
      [AC_MSG_ERROR([Validation testsuite requested, but CUnit was not found])],
      [test "x$test_vald" = "xcheck" -a "x$cunit_support" = "xno"],
      [AC_MSG_WARN([CUnit was not found, disabling validation testsuite])
       test_vald=no])

AM_CONDITIONAL([cunit_support], [test "x$cunit_support" = "xyes"])
AM_CONDITIONAL([test_vald], [test "x$test_vald" = "xyes"])

AC_SUBST([CUNIT_CFLAGS])
AC_SUBST([CUNIT_LIBS])
