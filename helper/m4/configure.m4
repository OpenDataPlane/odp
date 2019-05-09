##########################################################################
# Enable/disable test-helper
##########################################################################
AC_ARG_ENABLE([test-helper],
    [AS_HELP_STRING([--enable-test-helper], [run test in helper/test])],
    [test_helper=$enableval],
    [test_helper=yes])
AM_CONDITIONAL([test_helper], [test x$test_helper = xyes ])

##########################################################################
# Enable/disable Linux helpers
##########################################################################
AC_ARG_ENABLE([helper-linux],
    [AS_HELP_STRING([--disable-helper-linux], [disable Linux helpers])],
    [helper_linux=$enableval],
    [helper_linux=yes])

AC_CONFIG_FILES([helper/libodphelper.pc
		 helper/test/Makefile])
