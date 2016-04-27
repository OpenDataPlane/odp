##########################################################################
# Check for doxygen availability
##########################################################################
AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
   then AC_MSG_WARN([Doxygen not found - continuing without Doxygen support])
fi

##########################################################################
# Check for asciidoctor availability
##########################################################################
AC_CHECK_PROGS([ASCIIDOCTOR], [asciidoctor])
if test -z "$ASCIIDOCTOR";
   then AC_MSG_WARN([asciidoctor not found - continuing without asciidoctor support])
fi

##########################################################################
# Enable/disable user guide generation
##########################################################################
user_guides=no
AC_ARG_ENABLE([user-guides],
    [  --enable-user-guides    generate supplemental users guides],
    [if test "x$enableval" = "xyes"; then
        if test -z "$ASCIIDOCTOR";
           then AC_MSG_ERROR([cannot generate user guides without asciidoctor])
        else
           user_guides=yes
        fi
    fi])

##########################################################################
# Check for mscgen availability
##########################################################################
       AC_CHECK_PROGS([MSCGEN], [mscgen])
       if test -z "$MSCGEN";
          then AC_MSG_WARN([mscgen not found - continuing without sequence message support])
       fi

AC_CONFIG_FILES([doc/application-api-guide/Makefile
		 doc/implementers-guide/Makefile
		 doc/Makefile
		 doc/process-guide/Makefile
		 doc/users-guide/Makefile])
