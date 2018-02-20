AC_ARG_ENABLE([scheduler-default],
	      [AS_HELP_STRING([enable-scheduler-default],
			      [Choose default scheduler (default is basic)])],
	      [], [enable_scheduler_default=basic])
AC_DEFINE_UNQUOTED([ODP_SCHEDULE_DEFAULT], ["$enable_scheduler_default"],
		   [Define to name default scheduler])
