##########################################################################
# Enable/disable test-example
##########################################################################
test_example=no
AC_ARG_ENABLE([test-example],
    [  --enable-test-example   run basic test against examples],
    [if test "x$enableval" = "xyes"; then
        test_example=yes
     else
        test_example=no
    fi])

AC_CONFIG_FILES([example/classifier/Makefile
		 example/generator/Makefile
		 example/hello/Makefile
		 example/ipsec/Makefile
		 example/l2fwd_simple/Makefile
		 example/l3fwd/Makefile
		 example/packet/Makefile
		 example/switch/Makefile
		 example/time/Makefile
		 example/timer/Makefile
		 example/traffic_mgmt/Makefile
		 example/Makefile])
