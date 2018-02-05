##########################################################################
# Enable/disable test-helper
##########################################################################
AC_ARG_ENABLE([test-helper],
    [AS_HELP_STRING([--enable-test-helper], [run test in helper/test])],
    [test_helper=$enableval],
    [test_helper=yes])
AM_CONDITIONAL([test_helper], [test x$test_helper = xyes ])

##########################################################################
# Enable/disable helper-ext
# platform specific non portable extensions
##########################################################################
helper_linux=no
AC_ARG_ENABLE([helper-linux],
	[  --enable-helper-linux	build helper platform extensions (not portable)],
	[if test "x$enableval" = "xyes"; then
		helper_linux=yes
	fi])

AC_CONFIG_FILES([helper/Makefile
		 helper/libodphelper.pc
		 helper/test/Makefile])
