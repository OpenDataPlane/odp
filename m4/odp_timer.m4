# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2017 Linaro Limited
#

# ODP_TIMER([ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
##########################################################################
# Check for POSIX timer functions
##########################################################################
AC_DEFUN([ODP_TIMER], [dnl
AC_CHECK_LIB([rt], [timer_create], [TIMER_LIBS="-lrt"],
	     [AC_CHECK_LIB([posix4], [timer_create], [TIMER_LIBS="-lposix4"],
			   [m4_default([$2], [AC_MSG_FAILURE([timer_create not found])])])])
m4_default([$1], [:])
AC_SUBST([TIMER_LIBS])
]) # ODP_TIMER
