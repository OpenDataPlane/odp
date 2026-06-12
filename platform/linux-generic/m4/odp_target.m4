# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Nokia
#

# Target registry, grown by ODP_TARGET_REGISTER. The "default" target is always
# available and carries no per-target flags.
m4_define([_ODP_TARGET_NAMES], [default])
m4_define([_ODP_TARGET_CASES], [[default], []])

# ODP_TARGET_REGISTER(name, features)
# -------------------------------
# Register new target for '--with-target' configure option.
#
# Adding new target
# -----------------
# 1. Create (or edit) a *.m4 file under platform/linux-generic/m4/targets/. Any
#    *.m4 file in that directory is picked up automatically.
#
# 2. Call ODP_TARGET_REGISTER once per target. The first argument is the value
#    the user passes to --with-target; the second is a list of feature flags
#    that should be enabled when that target is selected, for example:
#
#        ODP_TARGET_REGISTER([my-cpu], [feature_1=yes
#                                       feature_2=yes])
#
# 3. Re-run ./bootstrap so the new target appears in configure.
#
m4_define([ODP_TARGET_REGISTER], [dnl
m4_define([_ODP_TARGET_NAMES],
	  m4_defn([_ODP_TARGET_NAMES])[, ]$1)dnl
m4_define([_ODP_TARGET_CASES],
	  m4_defn([_ODP_TARGET_CASES])[,
	  []$1[], [$2]])dnl
])

# Auto-include every targets/*.m4 file found at autoreconf time
m4_esyscmd_s([for f in platform/linux-generic/m4/targets/*.m4; do
	test -f "$f" && echo "m4_sinclude([$f])"
done])

# ODP_TARGET_OPTIONS
# ------------------
# Configure target-specific options
AC_DEFUN([ODP_TARGET_OPTIONS],
[
AC_ARG_WITH([target],
	    [AS_HELP_STRING([--with-target=TARGET],
		    [select target system [default=default]. Supported values: ]m4_defn([_ODP_TARGET_NAMES]))],
	    [ODP_TARGET=$with_target],
	    [ODP_TARGET=default
	     with_target=default])

# Set safe default values for all feature flags
feat_ecv=no
time_freq_1ghz=no

AS_CASE([$ODP_TARGET],
	_ODP_TARGET_CASES,
	[AC_MSG_ERROR([unsupported --with-target value '$ODP_TARGET'. Supported values: ]m4_defn([_ODP_TARGET_NAMES]))]
)

if test "x$feat_ecv" = "xyes"; then
	AC_DEFINE([_ODP_FEAT_ECV], [1],
		  [Define to 1 when FEAT_ECV is available])
fi
if test "x$time_freq_1ghz" = "xyes"; then
	AC_DEFINE([_ODP_TIME_FREQ_1GHZ], [1],
		  [Define to 1 when target has 1 GHz time counter frequency])
fi

])
