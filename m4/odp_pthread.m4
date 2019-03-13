# Copyright (c) 2018, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#
# ODP_PTHREAD
# -----------
# Check for pthreads availability
AC_DEFUN([ODP_PTHREAD], [
	AC_MSG_CHECKING([for pthread support in -pthread])
	AC_LANG_PUSH([C])
	PTHEAD_CFLAGS="-pthread"
	CFLAGS="$CFLAGS $PTHEAD_CFLAGS"
	PTHREAD_LIBS="-pthread"
	LDFLAGS="$LDFLAGS $PTHREAD_LIBS"
	AC_TRY_LINK_FUNC([pthread_create], [pthread=yes])
	if test x"$pthread" != "xyes"; then
		AC_MSG_FAILURE([pthread is not supported])
	fi
	AC_MSG_RESULT([yes])
	AC_LANG_POP([C])
	AC_SUBST([PTHREAD_LIBS])
	AC_SUBST([PTHREAD_CFLAGS])
])
