# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2017 Linaro Limited
#

# ODP_VISIBILITY
# --------------
# Enable -fvisibility=hidden if using a gcc that supports it

AC_DEFUN([ODP_VISIBILITY], [dnl
VISIBILITY_CFLAGS="-fvisibility=hidden"
AC_CACHE_CHECK([whether $CC supports -fvisibility=hidden],
	       [odp_cv_visibility_hidden], [dnl
OLD_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS $VISIBILITY_CFLAGS"
AC_LINK_IFELSE([AC_LANG_PROGRAM()], [odp_cv_visibility_hidden=yes],
       [odp_cv_visibility_hidden=no])
CFLAGS=$OLD_CFLAGS
])

if test "x$odp_cv_visibility_hidden" != "xyes" ; then
	VISIBILITY_CFLAGS=""
fi

AC_SUBST(VISIBILITY_CFLAGS)
]) # ODP_VISIBILITY
