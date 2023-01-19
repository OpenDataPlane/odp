##########################################################################
# Configuration file version
##########################################################################
m4_define([_odp_config_version_generation], [0])
m4_define([_odp_config_version_major], [1])
m4_define([_odp_config_version_minor], [25])

m4_define([_odp_config_version],
          [_odp_config_version_generation._odp_config_version_major._odp_config_version_minor])

_ODP_CONFIG_VERSION_GENERATION=_odp_config_version_generation
AC_SUBST(_ODP_CONFIG_VERSION_GENERATION)
_ODP_CONFIG_VERSION_MAJOR=_odp_config_version_major
AC_SUBST(_ODP_CONFIG_VERSION_MAJOR)
_ODP_CONFIG_VERSION_MINOR=_odp_config_version_minor
AC_SUBST(_ODP_CONFIG_VERSION_MINOR)

##########################################################################
# Set optional path for the default configuration file
##########################################################################
default_config_path="${srcdir}/config/odp-linux-generic.conf"

AC_CHECK_PROGS([REALPATH], [realpath])
AS_IF([test -z "$REALPATH"], [AC_MSG_ERROR([Could not find 'realpath'])])

AC_ARG_WITH([config-file],
AS_HELP_STRING([--with-config-file=FILE], [path to the default configuration file]
               [(this file must include all configuration options)]
               [[default=SRCDIR/config/odp-<platform>.conf]]),
            [default_config_path=$withval], [])

rel_default_config_path=`realpath --relative-to=$(pwd) ${default_config_path}`
AC_SUBST(default_config_path)
AC_SUBST(rel_default_config_path)

ODP_LIBCONFIG([linux-generic], [$rel_default_config_path])
