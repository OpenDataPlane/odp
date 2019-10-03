##########################################################################
# Enable netmap support
##########################################################################
netmap_support=no
AC_ARG_ENABLE([netmap_support],
    [  --enable-netmap-support  include netmap IO support],
    [if test x$enableval = xyes; then
        netmap_support=yes
    fi])

##########################################################################
# Set optional netmap path
##########################################################################
AC_ARG_WITH([netmap-path],
AS_HELP_STRING([--with-netmap-path=DIR   path to netmap root directory],
               [(or in the default path if not specified).]),
    [NETMAP_PATH=$withval
    NETMAP_CPPFLAGS="-isystem $NETMAP_PATH/sys"
    netmap_support=yes],[])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$NETMAP_CPPFLAGS $CPPFLAGS"

##########################################################################
# Check for netmap availability
##########################################################################
if test x$netmap_support = xyes
then
    AC_CHECK_HEADERS([net/netmap_user.h], [],
        [AC_MSG_FAILURE(["can't find netmap header"])])
    AC_DEFINE([_ODP_PKTIO_NETMAP], [1],
	      [Define to 1 to enable netmap packet I/O support])
    AC_SUBST([NETMAP_CPPFLAGS])
else
    netmap_support=no
fi

##########################################################################
# Restore old saved variables
##########################################################################
CPPFLAGS=$OLD_CPPFLAGS

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([netmap_support], [test x$netmap_support = xyes ])
])
