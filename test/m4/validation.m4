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
    AM_CPPFLAGS="$AM_CPPFLAGS -I$CUNIT_PATH/include"
    AM_LDFLAGS="$AM_LDFLAGS -L$CUNIT_PATH/lib"
    cunit_support=yes],[])

##########################################################################
# Check for CUnit availability
##########################################################################
if test x$cunit_support = xyes
then
    AC_CHECK_LIB([cunit],[CU_get_error], [],
        [AC_MSG_ERROR([CUnit libraries required])])
    AC_CHECK_HEADERS([CUnit/Basic.h], [],
        [AC_MSG_FAILURE(["can't find cunit headers"])])
else
    cunit_support=no
fi
