##########################################################################
# Check for dlopen and lt equivalent availability
##########################################################################

AC_SEARCH_LIBS([dlopen], [dl dld],
    [
       AM_LDFLAGS="$AM_LDFLAGS -ldl"
    ],
    [
       AC_MSG_ERROR([Error! dlopen not available!])
    ])
