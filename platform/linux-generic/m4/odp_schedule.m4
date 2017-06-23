# Checks for --enable-schedule-sp and defines ODP_SCHEDULE_SP and adds
# -DODP_SCHEDULE_SP to CFLAGS.
AC_ARG_ENABLE(
    [schedule_sp],
    [AC_HELP_STRING([--enable-schedule-sp],
                    [enable strict priority scheduler])],
    [if test "x$enableval" = xyes; then
         schedule_sp=true
         ODP_CFLAGS="$ODP_CFLAGS -DODP_SCHEDULE_SP"
     else
         schedule_sp=false
     fi],
    [schedule_sp=false])
AM_CONDITIONAL([ODP_SCHEDULE_SP], [test x$schedule_sp = xtrue])

# Checks for --enable-schedule-iquery and defines ODP_SCHEDULE_IQUERY and adds
# -DODP_SCHEDULE_IQUERY to CFLAGS.
AC_ARG_ENABLE(
    [schedule_iquery],
    [AC_HELP_STRING([--enable-schedule-iquery],
                    [enable interests query (sparse bitmap) scheduler])],
    [if test "x$enableval" = xyes; then
         schedule_iquery=true
         ODP_CFLAGS="$ODP_CFLAGS -DODP_SCHEDULE_IQUERY"
     else
         schedule_iquery=false
     fi],
    [schedule_iquery=false])
AM_CONDITIONAL([ODP_SCHEDULE_IQUERY], [test x$schedule_iquery = xtrue])

# Checks for --enable-schedule-scalable and defines ODP_SCHEDULE_SCALABLE and
# adds -DODP_SCHEDULE_SCALABLE to CFLAGS.
AC_ARG_ENABLE(
    [schedule_scalable],
    [AC_HELP_STRING([--enable-schedule-scalable],
                    [enable scalable scheduler])],
    [if test "x$enableval" = xyes; then
         schedule_scalable=true
         ODP_CFLAGS="$ODP_CFLAGS -DODP_SCHEDULE_SCALABLE"
     else
         schedule_scalable=false
     fi],
    [schedule_scalable=false])
AM_CONDITIONAL([ODP_SCHEDULE_SCALABLE], [test x$schedule_scalable = xtrue])
