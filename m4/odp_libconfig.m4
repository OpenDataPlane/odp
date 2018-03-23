# ODP_LIBCONFIG
# -------------
AC_DEFUN([ODP_LIBCONFIG],
[dnl
##########################################################################
# Check for libconfig availability
##########################################################################
PKG_CHECK_MODULES([LIBCONFIG], [libconfig])

##########################################################################
# Check for od availability
##########################################################################
AC_CHECK_PROGS([OD], [od])
AC_PROG_SED
AS_IF([test -z "$OD"], [AC_MSG_ERROR([Could not find 'od'])])

##########################################################################
# Create a header file odp_libconfig_config.h which containins null
# terminated hex dump of odp-linux.conf
##########################################################################
AC_CONFIG_COMMANDS([platform/${with_platform}/include/odp_libconfig_config.h],
[mkdir -p platform/${with_platform}/include
   (echo "static const char config_builtin[[]] = {"; \
     $OD -An -v -tx1 < ${srcdir}/config/odp-${with_platform}.conf | \
     $SED -e 's/[[0-9a-f]]\+/0x\0,/g' ; \
     echo "0x00 };") > \
   platform/${with_platform}/include/odp_libconfig_config.h],
 [with_platform=$with_platform OD=$OD SED=$SED])
]) # ODP_LIBCONFIG
