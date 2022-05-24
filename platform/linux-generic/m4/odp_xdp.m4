##########################################################################
# Check for libxdp availability
##########################################################################
AC_ARG_ENABLE([xdp], AS_HELP_STRING([--enable-xdp],
	      [enable experimental XDP support for Packet I/O [default=disabled] (linux-generic)]))

AS_IF([test "x$enable_xdp" = "xyes"], [
	PKG_CHECK_MODULES([LIBXDP], [libxdp >= 1.2.3],
	[
		AC_DEFINE(_ODP_PKTIO_XDP, [1], [Define to 1 to enable xdp packet I/O support])
	],
	[
		AS_IF([test "x$enable_xdp" == "xyes"], [AC_MSG_ERROR([libxdp not found])])
	])
])
