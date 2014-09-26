AC_PREREQ([2.5])
AC_INIT([OpenDataPlane], [0.2], [lng-odp@lists.linaro.org])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([helper/config.h.in])
AM_CONFIG_HEADER([helper/config.h])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])

DX_HTML_FEATURE(ON)
DX_PDF_FEATURE(ON)
DX_INIT_DOXYGEN($PACKAGE_NAME, doc/doxygen.cfg)

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
    [AS_HELP_STRING([--with-platform=prefix],
        [Select platform to be used, default linux-generic])],
    [],
    [with_platform=linux-generic])

AC_SUBST([with_platform])

AC_ARG_WITH([sdk-install-path],
AC_HELP_STRING([--with-sdk-install-path=DIR Path to external libs and headers],
               [(or in the default path if not specified).]),
[SDK_INSTALL_PATH=$withval SDK_INSTALL_PATH_=1],[SDK_INSTALL_PATH_=])

AC_SUBST(SDK_INSTALL_PATH)

AM_CONDITIONAL([SDK_INSTALL_PATH_], [test "x${SDK_INSTALL_PATH_}" = "x1"])

##########################################################################
# Enable/disable netmap support
##########################################################################
AC_ARG_ENABLE([netmap],
    [  --enable-netmap         Enable/disable netmap],
    [if test x$enableval = xyes; then
        netmap_support=yes
        ODP_CFLAGS="$ODP_CFLAGS -DODP_HAVE_NETMAP=1"
    fi])

AC_ARG_WITH([netmap-path],
AC_HELP_STRING([--with-netmap-path=DIR Path to netmap libs and headers],
               [(or in the default path if not specified).]),
[NETMAP_PATH=$withval netmap_support=yes
AM_CFLAGS="$AM_CFLAGS -I$NETMAP_PATH/sys"
ODP_CFLAGS="$ODP_CFLAGS -DODP_HAVE_NETMAP=1"
],[ AC_MSG_WARN([Netmap not found - continuing without netmap support])
])

AM_CONDITIONAL([ODP_NETMAP_ENABLED], [test x$netmap_support = xyes ])

##########################################################################
# Enable/disable ODP_DEBUG_PRINT
##########################################################################
ODP_DEBUG=1
AC_ARG_ENABLE([debug],
    [  --enable-debug         Enable/disable debug],
    [if ! test "x$enableval" = "xyes"; then
        ODP_DEBUG=0
    fi])
ODP_CFLAGS="$ODP_CFLAGS -DODP_DEBUG_PRINT=$ODP_DEBUG"

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

##########################################################################
# Check for openssl availability
##########################################################################

AC_ARG_WITH([openssl-path],
AC_HELP_STRING([--with-openssl-path=DIR Path to openssl libs and headers],
               [(or in the default path if not specified).]),
[OPENSSL_PATH=$withval
AM_CFLAGS="$AM_CFLAGS -I$OPENSSL_PATH/include"
AM_LDFLAGS="$AM_LDFLAGS -L$OPENSSL_PATH/lib -lcrypto"
],[
AC_CHECK_LIB([crypto], [EVP_EncryptInit], [],
             [AC_MSG_FAILURE([can't find openssl crypto lib])])
AC_CHECK_HEADERS([openssl/des.h openssl/rand.h openssl/hmac.h openssl/evp.h], [],
             [AC_MSG_FAILURE([can't find openssl crypto headers])])
    ])

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
		 platform/Makefile
		 platform/linux-generic/Makefile
		 platform/linux-keystone2/Makefile
		 example/Makefile
		 example/generator/Makefile
		 example/ipsec/Makefile
		 example/l2fwd/Makefile
		 example/odp_example/Makefile
		 example/packet/Makefile
		 example/packet_netmap/Makefile
		 example/timer/Makefile
		 test/Makefile
		 test/api_test/Makefile
		 pkgconfig/libodp.pc])

AC_SEARCH_LIBS([timer_create],[rt posix4])

##########################################################################
# distribute the changed variables among the Makefiles

AM_LDFLAGS="$AM_LDFLAGS -pthread -lrt"

AC_SUBST([LIBS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([CFLAGS])
AC_SUBST([AM_LDFLAGS])

AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE $VERSION
	========

	with_platform:		${with_platform}
	prefix:			${prefix}
	sysconfdir:		${sysconfdir}
	libdir:			${libdir}
	includedir:		${includedir}

	compiler:		${CC}
	cflags:			${CFLAGS}
	am_cflags:		${AM_CFLAGS}
	ldflags:		${LDFLAGS}
	am_ldflags:		${AM_LDFLAGS}
])
