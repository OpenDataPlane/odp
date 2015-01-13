AC_PREREQ([2.5])
AC_INIT([OpenDataPlane], m4_esyscmd(./scripts/odp_version.sh), [lng-odp@lists.linaro.org])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([helper/config.h.in])
AM_CONFIG_HEADER([helper/config.h])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])

DX_HTML_FEATURE(ON)
DX_PDF_FEATURE(ON)
DX_INIT_DOXYGEN($PACKAGE_NAME, doc/doxygen.cfg, doc/output)

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

AC_PROG_INSTALL
AC_PROG_MAKE_SET

#Use libtool
LT_INIT([])
AC_SUBST([LIBTOOL_DEPS])
AM_PROG_LIBTOOL

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

##########################################################################
# Determine which platform to build for
##########################################################################
AC_ARG_WITH([platform],
    [AS_HELP_STRING([--with-platform=platform],
        [select platform to be used, default linux-generic])],
    [],
    [with_platform=linux-generic])

AC_SUBST([with_platform])

AC_ARG_WITH([sdk-install-path],
AC_HELP_STRING([--with-sdk-install-path=DIR path to external libs and headers],
             [(or in the default path if not specified).]),
[SDK_INSTALL_PATH=$withval SDK_INSTALL_PATH_=1],[SDK_INSTALL_PATH_=])

AC_SUBST(SDK_INSTALL_PATH)

AM_CONDITIONAL([SDK_INSTALL_PATH_], [test "x${SDK_INSTALL_PATH_}" = "x1"])


##########################################################################
# Enable/disable Unit tests
##########################################################################
AC_ARG_ENABLE([cunit],
    [  --enable-cunit         Enable/disable cunit],
    [if test x$enableval = xyes; then
        cunit_support=yes
    fi])

##########################################################################
# Set optional CUnit path
##########################################################################
AC_ARG_WITH([cunit-path],
AC_HELP_STRING([--with-cunit-path=DIR Path to Cunit libs and headers],
               [(or in the default path if not specified).]),
    [CUNIT_PATH=$withval
    AM_CPPFLAGS="$AM_CPPFLAGS -I$CUNIT_PATH/include"
    AM_LDFLAGS="$AM_LDFLAGS -L$CUNIT_PATH/lib"
    cunit_support=yes],[])

##########################################################################
# Enable/disable ODP_DEBUG_PRINT
##########################################################################
ODP_DEBUG_PRINT=1
AC_ARG_ENABLE([debug-print],
    [  --enable-debug-print    display debugging information],
    [if ! test "x$enableval" = "xyes"; then
        ODP_DEBUG_PRINT=0
    fi])
ODP_CFLAGS="$ODP_CFLAGS -DODP_DEBUG_PRINT=$ODP_DEBUG_PRINT"

##########################################################################
# Enable/disable ODP_DEBUG
##########################################################################
ODP_DEBUG=1
AC_ARG_ENABLE([debug],
    [  --enable-debug          include additional code],
    [if ! test "x$enableval" = "xyes"; then
        ODP_DEBUG=0
    fi])
ODP_CFLAGS="$ODP_CFLAGS -DODP_DEBUG=$ODP_DEBUG"

##########################################################################
# Check for pthreads availability
##########################################################################

AX_PTHREAD([CC="$PTHREAD_CC"], [
    echo "Error! We require pthreads to be available"
    exit -1
    ])
LIBS="$PTHREAD_LIBS $LIBS"
AM_CFLAGS="$AM_CFLAGS $PTHREAD_CFLAGS"
AM_LDFLAGS="$AM_LDFLAGS $PTHREAD_LDFLAGS"

##########################################################################
# Check for doxygen availability
##########################################################################
AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
   then AC_MSG_WARN([Doxygen not found - continuing without Doxygen support])
fi

AM_CONDITIONAL([HAVE_DOXYGEN], [test "x${DOXYGEN}" = "xdoxygen"])

##########################################################################
# Set optional OpenSSL path
##########################################################################
AC_ARG_WITH([openssl-path],
AC_HELP_STRING([--with-openssl-path=DIR path to openssl libs and headers],
               [(or in the default path if not specified).]),
    [OPENSSL_PATH=$withval
    AM_CPPFLAGS="$AM_CPPFLAGS -I$OPENSSL_PATH/include"
    AM_LDFLAGS="$AM_LDFLAGS -L$OPENSSL_PATH/lib"
    ],[AC_MSG_RESULT([no])])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_LDFLAGS=$LDFLAGS
OLD_CPPFLAGS=$CPPFLAGS
LDFLAGS="$AM_LDFLAGS $LDFLAGS"
CPPFLAGS="$AM_CPPFLAGS $CPPFLAGS"

##########################################################################
# Check for CUnit availability
##########################################################################
if test x$cunit_support = xyes
then
    AC_CHECK_LIB([cunit],[CU_get_error], [],
        [AC_MSG_ERROR([CUnit libraries required])])
    AC_CHECK_HEADERS([CUnit/Basic.h], [],
        [AC_MSG_FAILURE(["can't find cunit headers"])])
else
    cunit_support=no
fi

AM_CONDITIONAL([ODP_CUNIT_ENABLED], [test x$cunit_support = xyes ])

##########################################################################
# Check for OpenSSL availability
##########################################################################
AC_CHECK_LIB([crypto], [EVP_EncryptInit], [],
             [AC_MSG_FAILURE([OpenSSL libraries required])])
AC_CHECK_HEADERS([openssl/des.h openssl/rand.h openssl/hmac.h openssl/evp.h], [],
             [AC_MSG_ERROR([OpenSSL headers required])])

##########################################################################
# Restore old saved variables
##########################################################################
LDFLAGS=$OLD_LDFLAGS
CPPFLAGS=$OLD_CPPFLAGS

##########################################################################
# Default warning setup
##########################################################################
ODP_CFLAGS="$ODP_CFLAGS -W -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes"
ODP_CFLAGS="$ODP_CFLAGS -Wmissing-declarations -Wold-style-definition -Wpointer-arith"
ODP_CFLAGS="$ODP_CFLAGS -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral"
ODP_CFLAGS="$ODP_CFLAGS -Wformat-security -Wundef -Wwrite-strings"

##########################################################################
# Default include setup
##########################################################################
AM_CFLAGS="$AM_CFLAGS $ODP_CFLAGS"

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero clock_gettime gethostbyname getpagesize gettimeofday memset munmap socket strchr strerror strrchr strstr strtoull])

AC_CONFIG_FILES([Makefile
		 doc/Makefile
		 example/Makefile
		 example/generator/Makefile
		 example/ipsec/Makefile
		 example/l2fwd/Makefile
		 example/packet/Makefile
		 example/timer/Makefile
		 pkgconfig/libodp.pc
		 platform/Makefile
		 platform/linux-generic/Makefile
		 test/Makefile
		 test/api_test/Makefile
		 test/performance/Makefile
		 test/validation/Makefile
		 ])

AC_SEARCH_LIBS([timer_create],[rt posix4])

##########################################################################
# distribute the changed variables among the Makefiles

AM_LDFLAGS="$AM_LDFLAGS -pthread -lrt"

AC_SUBST([LIBS])
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([CFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([LDFLAGS])

AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE $VERSION
	========

	with_platform:		${with_platform}
	prefix:			${prefix}
	sysconfdir:		${sysconfdir}
	libdir:			${libdir}
	includedir:		${includedir}

	cc:			${CC}
	cppflags:		${CPPFLAGS}
	am_cppflags:		${AM_CPPFLAGS}
	cflags:			${CFLAGS}
	am_cflags:		${AM_CFLAGS}
	ldflags:		${LDFLAGS}
	am_ldflags:		${AM_LDFLAGS}
	libs:			${LIBS}
	cunit:			${cunit_support}
])
