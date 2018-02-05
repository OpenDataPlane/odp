# ODP_PTHREAD
# -----------
# Check for pthreads availability
AC_DEFUN([ODP_PTHREAD], [dnl
AX_PTHREAD([CC="$PTHREAD_CC"],
	   [AC_MSG_FAILURE([We require pthreads to be available])])
])
