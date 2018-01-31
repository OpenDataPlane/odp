##########################################################################
# Enable/disable Unit tests
##########################################################################
AC_ARG_ENABLE([test_vald],
    [AS_HELP_STRING([--enable-test-vald], [run test in test/validation])],
    [test_vald=$enableval],
    [test_vald=yes])
AM_CONDITIONAL([test_vald], [test x$test_vald = xyes ])

##########################################################################
# Set optional CUnit path
##########################################################################
cunit_support=$test_vald
AC_ARG_WITH([cunit-path],
AC_HELP_STRING([--with-cunit-path=DIR],
	       [path to CUnit libs and headers (if not present at default path)]),
    [CUNIT_PATH=$withval
     CUNIT_CPPFLAGS="-I$CUNIT_PATH/include"
     CUNIT_LIBS="-L$CUNIT_PATH/lib"
     cunit_support=yes],[])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_LIBS=$LIBS
OLD_CPPFLAGS=$CPPFLAGS
LIBS="$CUNIT_LIBS $LIBS"
CPPFLAGS="$CUNIT_CPPFLAGS $CPPFLAGS"

##########################################################################
# Check for CUnit availability
##########################################################################
if test x$cunit_support = xyes
then
    AC_CHECK_LIB([cunit],[CU_get_error], [CUNIT_LIBS="$CUNIT_LIBS -lcunit"],
        [AC_MSG_ERROR([CUnit libraries required])])
    AC_CHECK_HEADERS([CUnit/Basic.h], [],
        [AC_MSG_FAILURE(["can't find cunit headers"])])
else
    cunit_support=no
fi

AC_SUBST([CUNIT_CPPFLAGS])
AC_SUBST([CUNIT_LIBS])

##########################################################################
# Restore old saved variables
##########################################################################
LIBS=$OLD_LIBS
CPPFLAGS=$OLD_CPPFLAGS
