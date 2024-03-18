# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022 Nokia
#

# ODP_EVENT_VALIDATION
# --------------------
# Select event validation level
AC_DEFUN([ODP_EVENT_VALIDATION], [dnl
AC_ARG_ENABLE([event-validation],
	      [AS_HELP_STRING([--enable-event-validation],
			      [enable event validation (warn/abort)
			      [default=disabled] (linux-generic)])],
	      [], [AS_IF([test "x$enable_debug" = "xfull"],
	      		 [enable_event_validation=yes], [enable_event_validation=no])])

# Default to abort mode if validation is enabled
AS_IF([test "x$enable_event_validation" = "xyes"],
      [enable_event_validation="abort"])

validation_level=0
AS_IF([test "x$enable_event_validation" = "xwarn"], [validation_level=1])
AS_IF([test "x$enable_event_validation" = "xyes" -o "x$enable_event_validation" = "xabort"],
      [validation_level=2])

AC_DEFINE_UNQUOTED([_ODP_EVENT_VALIDATION], [$validation_level],
		   [Define to 1 or 2 to enable event validation])
]) # ODP_EVENT_VALIDATION
