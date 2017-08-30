##########################################################################
# Enable/disable Unit tests
##########################################################################
AC_ARG_ENABLE([test_vald],
    [AS_HELP_STRING([--enable-test-vald], [run test in test/validation])],
    [test_vald=$enableval],
    [test_vald=yes])
AM_CONDITIONAL([test_vald], [test x$test_vald = xyes ])

##########################################################################
# Check for CUnit availability
##########################################################################
cunit_support=$test_vald
AS_IF([test "x$cunit_support" = "xyes"],
      [PKG_CHECK_MODULES([CUNIT], [cunit])])

AC_SUBST([CUNIT_CFLAGS])
AC_SUBST([CUNIT_LIBS])
