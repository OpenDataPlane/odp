AC_ARG_ENABLE([schedule-sp],
    [  --enable-schedule-sp    enable strict priority scheduler],
    [if test x$enableval = xyes; then
	schedule_sp_enabled=yes
	AC_DEFINE([ODP_SCHEDULE_SP], [1],
		  [Define to 1 to enable strict priority scheduler])
    fi])
AM_CONDITIONAL([ODP_SCHEDULE_SP], [test x$schedule_sp_enabled = xyes])

AC_ARG_ENABLE([schedule-iquery],
    [  --enable-schedule-iquery    enable interests query (sparse bitmap) scheduler],
    [if test x$enableval = xyes; then
	schedule_iquery_enabled=yes
	AC_DEFINE([ODP_SCHEDULE_IQUERY], [1],
		  [Define to 1 to enable interests query scheduler])
    fi])
AM_CONDITIONAL([ODP_SCHEDULE_IQUERY], [test x$schedule_iquery_enabled = xyes])

AC_ARG_ENABLE([schedule_scalable],
    [  --enable-schedule-scalable   enable scalable scheduler],
    [if test x$enableval = xyes; then
	schedule_scalable_enabled=yes
	AC_DEFINE([ODP_SCHEDULE_SCALABLE], [1],
		  [Define to 1 to enable scalable scheduler])
    fi])
AM_CONDITIONAL([ODP_SCHEDULE_SCALABLE], [test x$schedule_scalable_enabled = xyes])
