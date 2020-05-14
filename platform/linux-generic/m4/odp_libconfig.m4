##########################################################################
# Configuration file version
##########################################################################
m4_define([_odp_config_version_generation], [0])
m4_define([_odp_config_version_major], [1])
m4_define([_odp_config_version_minor], [13])

m4_define([_odp_config_version],
          [_odp_config_version_generation._odp_config_version_major._odp_config_version_minor])

_ODP_CONFIG_VERSION_GENERATION=_odp_config_version_generation
AC_SUBST(_ODP_CONFIG_VERSION_GENERATION)
_ODP_CONFIG_VERSION_MAJOR=_odp_config_version_major
AC_SUBST(_ODP_CONFIG_VERSION_MAJOR)
_ODP_CONFIG_VERSION_MINOR=_odp_config_version_minor
AC_SUBST(_ODP_CONFIG_VERSION_MINOR)

ODP_LIBCONFIG([$with_platform])
