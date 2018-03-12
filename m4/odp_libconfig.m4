# ODP_LIBCONFIG
# -------------
AC_DEFUN([ODP_LIBCONFIG],
[dnl
##########################################################################
# Check for libconfig availability
##########################################################################
PKG_CHECK_MODULES([LIBCONFIG], [libconfig])

##########################################################################
# Check for xxd availability
##########################################################################
AC_CHECK_PROGS([XXD], [xxd])
if test -z "$XXD";
   then AC_MSG_ERROR([Could not find 'xxd'])
fi

##########################################################################
# Create a header file odp_libconfig_config.h which containins null
# terminated hex dump of odp-linux.conf
##########################################################################
AC_CONFIG_COMMANDS([platform/${with_platform}/include/odp_libconfig_config.h],
[mkdir -p platform/${with_platform}/include
 (cd ${srcdir}/config ; xxd -i odp-${with_platform}.conf) | \
   sed 's/\([[0-9a-f]]\)$/\0, 0x00/' > \
   platform/${with_platform}/include/odp_libconfig_config.h],
 [with_platform=$with_platform])
]) # ODP_LIBCONFIG
