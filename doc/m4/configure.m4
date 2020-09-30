##########################################################################
# Check for asciidoctor availability
##########################################################################
AC_CHECK_PROGS([ASCIIDOCTOR], [asciidoctor])
if test -z "$ASCIIDOCTOR";
   then AC_MSG_WARN([asciidoctor not found - continuing without asciidoctor support])
fi

##########################################################################
# Check for mscgen availability
##########################################################################
AC_CHECK_PROGS([MSCGEN], [mscgen])
if test -z "$MSCGEN";
   then AC_MSG_WARN([mscgen not found - continuing without sequence message support])
fi

##########################################################################
# Check for dot availability
##########################################################################
AC_CHECK_PROGS([DOT], [dot])
if test -z "$DOT";
   then AC_MSG_WARN([dot not found - continuing without dot graphics support])
fi

##########################################################################
# Enable/disable user guide generation
##########################################################################
user_guides=no
AC_ARG_ENABLE([user-guides],
    [AS_HELP_STRING([--enable-user-guides],
                    [generate supplemental users guides [default=disabled]])],
    [if test "x$enableval" = "xyes"; then
        if test -z "$ASCIIDOCTOR";
           then AC_MSG_ERROR([cannot generate user guides without asciidoctor])
        fi
        if test -z "$MSCGEN";
           then AC_MSG_ERROR([cannot generate user guides without mscgen])
        fi
        if test -z "$DOT";
           then AC_MSG_ERROR([cannot generate user guides without dot])
        fi
        user_guides=yes
    fi])

AC_CONFIG_FILES([doc/application-api-guide/Makefile
		 doc/helper-guide/Makefile
		 doc/implementers-guide/Makefile
		 doc/Makefile
		 doc/platform-api-guide/Makefile
		 doc/process-guide/Makefile
		 doc/users-guide/Makefile])
