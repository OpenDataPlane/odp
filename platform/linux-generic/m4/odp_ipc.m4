##########################################################################
# Enable IPC pktio support
##########################################################################
AC_ARG_ENABLE([pktio_ipc_support],
    [  --enable-pktio_ipc-support  include ipc IO support],
    [if test x$enableval = xyes; then
	pktio_ipc_support=yes
	ODP_CFLAGS="$ODP_CFLAGS -D_ODP_PKTIO_IPC"
    fi])
