##########################################################################
# Enable mdev support
##########################################################################
mdev_support=no
AC_ARG_ENABLE([mdev_support],
    [  --enable-mdev-support  include mediated device drivers support],
    [if test x$enableval = xyes; then
        mdev_support=yes
    fi])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$MDEV_CPPFLAGS $CPPFLAGS"

##########################################################################
# Check for mdev availability
##########################################################################
if test x$mdev_support = xyes
then
    AC_DEFINE([ODP_MDEV], [1],
	      [Define to 1 to enable mediated device drivers support])
    AC_SUBST([MDEV_CPPFLAGS])
else
    mdev_support=no
fi

##########################################################################
# Restore old saved variables
##########################################################################
CPPFLAGS=$OLD_CPPFLAGS

AM_CONDITIONAL([mdev_support], [test x$mdev_support = xyes ])
