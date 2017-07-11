##########################################################################
# Enable/disable Unit tests
##########################################################################
cunit_support=no
test_vald=no
AC_ARG_ENABLE([test_vald],
    [  --enable-test-vald       run test in test/validation],
    [if test x$enableval = xyes; then
        test_vald=yes
        cunit_support=yes
    fi])

##########################################################################
# Enable/disable Unit tests
##########################################################################
AC_ARG_ENABLE([cunit_support],
    [  --enable-cunit-support  include cunit infrastructure],
    [if test x$enableval = xyes; then
        cunit_support=yes
    fi])

##########################################################################
# Set optional CUnit path
##########################################################################
AC_ARG_WITH([cunit-path],
AC_HELP_STRING([--with-cunit-path=DIR   path to CUnit libs and headers],
               [(or in the default path if not specified).]),
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
