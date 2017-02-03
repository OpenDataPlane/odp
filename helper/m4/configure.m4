##########################################################################
# Enable/disable test-helper
##########################################################################
test_helper=no
AC_ARG_ENABLE([test-helper],
    [  --enable-test-helper      run test in helper/test],
    [if test "x$enableval" = "xyes"; then
        test_helper=yes
    fi])

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
		helper/test/Makefile])
