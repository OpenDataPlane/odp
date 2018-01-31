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
      [PKG_CHECK_MODULES([CUNIT], [cunit], [],
      [AC_MSG_WARN([pkg-config could not find CUnit, guessing])
    AC_CHECK_HEADERS([CUnit/Basic.h], [],
        [AC_MSG_ERROR(["can't find CUnit headers"])])
    AC_CHECK_LIB([cunit],[CU_get_error], [CUNIT_LIBS="-lcunit"],
        [AC_MSG_ERROR([CUnit libraries required])])
])])

AC_SUBST([CUNIT_CFLAGS])
AC_SUBST([CUNIT_LIBS])
