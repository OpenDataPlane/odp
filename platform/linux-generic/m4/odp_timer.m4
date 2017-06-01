##########################################################################
# Check for POSIX timer functions
##########################################################################

AC_CHECK_LIB([rt], [timer_create], [TIMER_LIBS="-lrt"],
	     [AC_CHECK_LIB([posix4], [timer_create], [TIMER_LIBS="-lposix4"],
			   [AC_MSG_FAILURE([timer_create not found])])])
AC_SUBST([TIMER_LIBS])
