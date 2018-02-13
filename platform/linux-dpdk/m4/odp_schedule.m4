AC_ARG_ENABLE([schedule-sp],
    [  --enable-schedule-sp    enable strict priority scheduler],
    [if test x$enableval = xyes; then
	schedule_sp_enabled=yes
	AC_DEFINE([ODP_SCHEDULE_SP], [1],
		  [Define to 1 to enable strict priority scheduler])
    fi])

AC_ARG_ENABLE([schedule-iquery],
    [  --enable-schedule-iquery    enable interests query (sparse bitmap) scheduler],
    [if test x$enableval = xyes; then
	schedule_iquery_enabled=yes
	AC_DEFINE([ODP_SCHEDULE_IQUERY], [1],
		  [Define to 1 to enable interests query scheduler])
    fi])
