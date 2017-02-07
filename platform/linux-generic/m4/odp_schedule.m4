AC_ARG_ENABLE([schedule-sp],
    [  --enable-schedule-sp    enable strict priority scheduler],
    [if test x$enableval = xyes; then
	schedule_sp_enabled=yes
	ODP_CFLAGS="$ODP_CFLAGS -DODP_SCHEDULE_SP"
    fi])

AC_ARG_ENABLE([schedule-iquery],
    [  --enable-schedule-iquery    enable interests query (sparse bitmap) scheduler],
    [if test x$enableval = xyes; then
	schedule_iquery_enabled=yes
	ODP_CFLAGS="$ODP_CFLAGS -DODP_SCHEDULE_IQUERY"
    fi])
