# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Nokia
#

##########################################################################
# Enable/disable WFE based lock implementations
##########################################################################
use_wfe_locks=no
AC_ARG_ENABLE([wfe-locks],
	      [AS_HELP_STRING([--enable-wfe-locks],
			      [enable WFE based lock implementations on aarch64]
			      [[default=disabled] (linux-generic)])],
	      [use_wfe_locks=$enableval])

if test x$use_wfe_locks = xyes; then
    AC_DEFINE([_ODP_WFE_LOCKS], [1],
    	      [Define to 1 to enable WFE based lock implementations on aarch64])
fi
