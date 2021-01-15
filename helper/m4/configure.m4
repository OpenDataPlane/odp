##########################################################################
# Enable/disable test-helper
##########################################################################
AC_ARG_ENABLE([test-helper],
    [AS_HELP_STRING([--enable-test-helper],
		    [run test in helper/test [default=enabled]])],
    [test_helper=$enableval],
    [test_helper=yes])
AM_CONDITIONAL([test_helper], [test x$test_helper = xyes ])

##########################################################################
# Enable/disable Linux helpers
##########################################################################
AC_ARG_ENABLE([helper-linux],
    [AS_HELP_STRING([--disable-helper-linux],
		   [disable Linux helpers [default=enabled]])],
    [helper_linux=$enableval],
    [helper_linux=yes])

##########################################################################
# Enable/disable ODPH_DEBUG
##########################################################################
AC_ARG_ENABLE([helper-debug],
    [AS_HELP_STRING([--enable-helper-debug],
		    [helpers include additional debugging code [default=disabled]])],
    [], [AS_IF([test "x$enable_debug" = "xfull"], [enable_helper_debug=yes],
    [enable_helper_debug=no])])
AS_IF([test "x$enable_helper_debug" != "xno"], [ODPH_DEBUG=1], [ODPH_DEBUG=0])
AC_DEFINE_UNQUOTED([ODPH_DEBUG], [$ODPH_DEBUG],
		   [Define to 1 to include additional helper debug code])

##########################################################################
# Enable/disable ODPH_DEBUG_PRINT
##########################################################################
AC_ARG_ENABLE([helper-debug-print],
    [AS_HELP_STRING([--enable-helper-debug-print],
		    [display helper debugging information [default=disabled]])],
    [], [AS_IF([test "x$enable_debug" = "xfull"], [enable_helper_debug_print=yes],
	       [enable_helper_debug_print=no])])
AS_IF([test "x$enable_helper_debug_print" != "xno"], [ODPH_DEBUG_PRINT=1],
      [ODPH_DEBUG_PRINT=0])
AC_DEFINE_UNQUOTED([ODPH_DEBUG_PRINT], [$ODPH_DEBUG_PRINT],
		   [Define to 1 to display helper debug information])

#########################################################################
# If libcli is available, enable CLI helper
#########################################################################
helper_cli=no
AC_CHECK_HEADER(libcli.h,
    [AC_CHECK_LIB(cli, cli_init, [helper_cli=yes], [], [-lcrypt])],
    [])

LIBCLI_LIBS=""
AS_IF([test "x$helper_cli" != "xno"],
    [AC_DEFINE_UNQUOTED([ODPH_CLI], [1], [Define to 1 to enable CLI helper])
        LIBCLI_LIBS="-lcli -lcrypt"])

AC_SUBST([LIBCLI_LIBS])

AC_CONFIG_FILES([helper/libodphelper.pc
		 helper/test/Makefile])
