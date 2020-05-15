# ODP_LIBCONFIG(PLATFORM, CONFIG-FILE-PATH)
# -----------------------------------------
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
# Check default configuration file
##########################################################################
AS_IF([test -z "$2"] || [test ! -f $2],
      [AC_MSG_ERROR([Default configuration file not found])], [])

odp_use_config=true
##########################################################################
# Create a header file odp_libconfig_config.h which containins null
# terminated hex dump of odp-linux.conf
##########################################################################
AC_CONFIG_COMMANDS([platform/$1/include/odp_libconfig_config.h],
[mkdir -p platform/$1/include
   (echo "static const char config_builtin[[]] = {"; \
     $OD -An -v -tx1 < $CONFIG_FILE | \
     $SED -e 's/[[0-9a-f]]\+/0x\0,/g' ; \
     echo "0x00 };") > \
   platform/$1/include/odp_libconfig_config.h],
 [with_platform=$1 OD=$OD SED=$SED CONFIG_FILE=$2])
]) # ODP_LIBCONFIG
