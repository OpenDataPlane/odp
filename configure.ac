AC_PREREQ([2.5])
##########################################################################
# Set correct API version
##########################################################################
m4_define([odpapi_generation_version], [1])
m4_define([odpapi_major_version], [13])
m4_define([odpapi_minor_version], [0])
m4_define([odpapi_point_version], [0])
m4_define([odpapi_version],
    [odpapi_generation_version.odpapi_major_version.odpapi_minor_version.odpapi_point_version])
AC_INIT([OpenDataPlane],[odpapi_version],[lng-odp@lists.linaro.org])

ODP_VERSION_API_GENERATION=odpapi_generation_version
AC_SUBST(ODP_VERSION_API_GENERATION)
ODP_VERSION_API_MAJOR=odpapi_major_version
AC_SUBST(ODP_VERSION_API_MAJOR)
ODP_VERSION_API_MINOR=odpapi_minor_version
AC_SUBST(ODP_VERSION_API_MINOR)
AC_CONFIG_FILES([include/odp/api/spec/version.h])

AM_INIT_AUTOMAKE([1.9 tar-pax subdir-objects])
AC_CONFIG_SRCDIR([helper/config.h.in])
AM_CONFIG_HEADER([helper/config.h])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])

##########################################################################
# Set platform library version
#
# Follow version rules described here:
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
# Version is Current:Revision:Age
# 1. if there are only source changes, use C:R+1:A
# 2. if interfaces were added use C+1:0:A+1
# 3. if interfaces were removed, then use C+1:0:0
##########################################################################

ODP_LIBSO_VERSION=113:0:0
AC_SUBST(ODP_LIBSO_VERSION)

ODPHELPER_LIBSO_VERSION=111:0:2
AC_SUBST(ODPHELPER_LIBSO_VERSION)

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

AC_PROG_CXX

AC_PROG_INSTALL
AC_PROG_MAKE_SET

AM_PROG_AR
#Use libtool
LT_INIT([])
AC_SUBST([LIBTOOL_DEPS])
AM_PROG_LIBTOOL

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero clock_gettime gethostbyname getpagesize gettimeofday memset munmap socket strchr strerror strrchr strstr strtoull])

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

#########################################################################
# Get GCC version
#########################################################################

AX_COMPILER_VERSION
CC_VERSION=$ax_cv_c_compiler_version

CC_VERSION_MAJOR=$(echo $CC_VERSION | cut -d'.' -f1)
CC_VERSION_MINOR=$(echo $CC_VERSION | cut -d'.' -f2)
CC_VERSION_PATCH=$(echo $CC_VERSION | cut -d'.' -f3)

##########################################################################
# Allow valgrind suite to run against the defined tests
##########################################################################
AX_VALGRIND_CHECK

##########################################################################
# Which architecture optimizations will we use
##########################################################################
AS_CASE([$host],
  [x86*], [ARCH_DIR=x86],
  [i686*], [ARCH_DIR=x86],
  [mips64*], [ARCH_DIR=mips64],
  [powerpc*], [ARCH_DIR=powerpc],
  [aarch64*], [ARCH_DIR=arm],
  [arm*], [ARCH_DIR=arm],
  [ARCH_DIR=undefined]
)
AC_SUBST([ARCH_DIR])

##########################################################################
# Warn on the defaults if arch is undefined
##########################################################################
if test "${ARCH_DIR}" == "undefined";
then
    echo "ARCH_DIR is undefined, please add your ARCH_DIR based on host=${host}"
    exit 1
fi

##########################################################################
# Set correct pkgconfig version
##########################################################################
PKGCONFIG_VERSION=$(echo $VERSION | awk -F '.git' '{print $1}')
AC_SUBST(PKGCONFIG_VERSION)

##########################################################################
# Determine which platform to build for
##########################################################################
AC_ARG_WITH([platform],
    [AS_HELP_STRING([--with-platform=platform],
	[select platform to be used, default linux-generic])],
    [],
    [with_platform=linux-generic
    ])

AC_SUBST([with_platform])
AC_SUBST([platform_with_platform], ["platform/${with_platform}"])

##########################################################################
# Determine which helper platform to build for
##########################################################################
AC_ARG_WITH([helper_platform],
    [AS_HELP_STRING([--with-helper_platform=platform],
	[select helper platform to be used, default linux-generic])],
    [],
    [with_helper_platform=${with_platform}
    ])

AC_SUBST([with_helper_platform])

##########################################################################
# Run platform specific checks and settings
##########################################################################
IMPLEMENTATION_NAME=""
if test "${with_platform}" == "linux-generic";
then
    m4_include([./platform/linux-generic/m4/configure.m4])
    m4_include([./test/linux-generic/m4/configure.m4])
    IMPLEMENTATION_NAME="odp-linux"
else
    echo "UNSUPPORTED PLATFORM: ${with_platform}"
    exit 1
fi

ODP_CFLAGS="$ODP_CFLAGS -DIMPLEMENTATION_NAME=$IMPLEMENTATION_NAME"

##########################################################################
# Include m4 files
##########################################################################
m4_include([./doc/m4/configure.m4])
m4_include([./example/m4/configure.m4])
m4_include([./helper/m4/configure.m4])
m4_include([./test/m4/configure.m4])

##########################################################################
# Set SDK install path
##########################################################################
AC_ARG_WITH([sdk-install-path],
AC_HELP_STRING([--with-sdk-install-path=DIR path to external libs and headers],
	     [(or in the default path if not specified).]),
[SDK_INSTALL_PATH=$withval SDK_INSTALL_PATH_=1],[SDK_INSTALL_PATH_=])

AC_SUBST(SDK_INSTALL_PATH)

##########################################################################
# Set the install directory for test binaries/scripts
##########################################################################
AC_ARG_WITH([testdir],
    AC_HELP_STRING([--with-testdir=DIR installation directory for tests]),
	[if test "$withval" = "yes"; then
	     testdir=$libdir/odp/tests
	 else
	     testdir=$withval
	 fi], [])
AC_SUBST([testdir])

##########################################################################
# Set conditionals as computed within platform specific files
##########################################################################
AM_CONDITIONAL([netmap_support], [test x$netmap_support = xyes ])
AM_CONDITIONAL([PKTIO_IPC], [test x$pktio_ipc_support = xyes])
AM_CONDITIONAL([PKTIO_DPDK], [test x$pktio_dpdk_support = xyes ])
AM_CONDITIONAL([HAVE_PCAP], [test $have_pcap = yes])
AM_CONDITIONAL([SDK_INSTALL_PATH_], [test "x${SDK_INSTALL_PATH_}" = "x1"])
AM_CONDITIONAL([test_installdir], [test "$testdir" != ""])
AM_CONDITIONAL([cunit_support], [test x$cunit_support = xyes ])
AM_CONDITIONAL([test_vald], [test x$test_vald = xyes ])
AM_CONDITIONAL([test_perf], [test x$test_perf = xyes ])
AM_CONDITIONAL([test_perf_proc], [test x$test_perf_proc = xyes ])
AM_CONDITIONAL([test_cpp], [test x$test_cpp = xyes ])
AM_CONDITIONAL([test_helper], [test x$test_helper = xyes ])
AM_CONDITIONAL([test_example], [test x$test_example = xyes ])
AM_CONDITIONAL([HAVE_DOXYGEN], [test "x${DOXYGEN}" = "xdoxygen"])
AM_CONDITIONAL([user_guide], [test "x${user_guides}" = "xyes" ])
AM_CONDITIONAL([HAVE_MSCGEN], [test "x${MSCGEN}" = "xmscgen"])
AM_CONDITIONAL([helper_extn], [test x$helper_extn = xyes ])

##########################################################################
# Setup doxygen documentation
##########################################################################
DX_HTML_FEATURE(ON)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN($PACKAGE_NAME,
		${srcdir}/doc/application-api-guide/Doxyfile,
		${builddir}/doc/application-api-guide/output,
		${srcdir}/doc/helper-guide/Doxyfile,
		${builddir}/doc/helper-guide/output,
		${srcdir}/doc/platform-api-guide/Doxyfile,
		${builddir}/doc/platform-api-guide/output,
		${srcdir}/doc/driver-api-guide/Doxyfile,
		${builddir}/doc/driver-api-guide/output)

##########################################################################
# Enable/disable ODP_DEBUG_PRINT
##########################################################################
ODP_DEBUG_PRINT=0
AC_ARG_ENABLE([debug-print],
    [  --enable-debug-print    display debugging information],
    [if test "x$enableval" = "xyes"; then
	ODP_DEBUG_PRINT=1
     else
	ODP_DEBUG_PRINT=0
    fi])
ODP_CFLAGS="$ODP_CFLAGS -DODP_DEBUG_PRINT=$ODP_DEBUG_PRINT"

##########################################################################
# Enable/disable ODP_DEBUG
##########################################################################
ODP_DEBUG=0
AC_ARG_ENABLE([debug],
    [  --enable-debug          include additional code],
    [if test "x$enableval" = "xyes"; then
	ODP_DEBUG=1
     else
	ODP_DEBUG=0
    fi])
ODP_CFLAGS="$ODP_CFLAGS -DODP_DEBUG=$ODP_DEBUG"

##########################################################################
# Enable/disable ABI compatible build
##########################################################################
ODP_ABI_COMPAT=1
abi_compat=yes
AC_ARG_ENABLE([abi-compat],
    [  --disable-abi-compat     disables ABI compatible mode, enables inline code in header files],
    [if test "x$enableval" = "xno"; then
	ODP_ABI_COMPAT=0
	abi_compat=no
	#if there is no ABI compatibility the .so numbers are meaningless
	ODP_LIBSO_VERSION=0:0:0
    fi])
AC_SUBST(ODP_ABI_COMPAT)

##########################################################################
# Default warning setup
##########################################################################
ODP_CFLAGS="$ODP_CFLAGS -W -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes"
ODP_CFLAGS="$ODP_CFLAGS -Wmissing-declarations -Wold-style-definition -Wpointer-arith"
ODP_CFLAGS="$ODP_CFLAGS -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral"
ODP_CFLAGS="$ODP_CFLAGS -Wformat-security -Wundef -Wwrite-strings"
ODP_CFLAGS="$ODP_CFLAGS -std=c99"
# Extra flags for example to suppress certain warning types
ODP_CFLAGS="$ODP_CFLAGS $ODP_CFLAGS_EXTRA"

#########################################################################
# Check if compiler supports cmpxchng16
##########################################################################
if test "${CC}" != "gcc" -o ${CC_VERSION_MAJOR} -ge 5; then
   my_save_cflags="$CFLAGS"

   CFLAGS=-mcx16
   AC_MSG_CHECKING([whether CC supports -mcx16])
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
	    [AC_MSG_RESULT([yes])]
	    [ODP_CFLAGS="$ODP_CFLAGS $CFLAGS"],
	    [AC_MSG_RESULT([no])]
	    )
   CFLAGS="$my_save_cflags"
fi

##########################################################################
# Default include setup
##########################################################################
AM_CFLAGS="$AM_CFLAGS $ODP_CFLAGS"
AM_CXXFLAGS="-std=c++11"

AC_CONFIG_FILES([Makefile
		 pkgconfig/libodp-linux.pc
		 pkgconfig/libodphelper-linux-generic.pc
		 ])

AC_SEARCH_LIBS([timer_create],[rt posix4])

##########################################################################
# distribute the changed variables among the Makefiles

AC_SUBST([LIBS])
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([CFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([LDFLAGS])
AC_SUBST([EXEEXT])

AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE $VERSION

	ODP Library version:	${ODP_LIBSO_VERSION}
	Helper Library version:	${ODPHELPER_LIBSO_VERSION}

	implementation_name:	${IMPLEMENTATION_NAME}
	ARCH_DIR		${ARCH_DIR}
	with_platform:		${with_platform}
	with_helper_platform:	${with_helper_platform}
	helper_extn:		${helper_extn}
	prefix:			${prefix}
	sysconfdir:		${sysconfdir}
	libdir:			${libdir}
	includedir:		${includedir}
	testdir:		${testdir}
	WITH_ARCH:              ${WITH_ARCH}

	cc:			${CC}
	cc version:             ${CC_VERSION}
	cppflags:		${CPPFLAGS}
	am_cppflags:		${AM_CPPFLAGS}
	am_cxxflags:		${AM_CXXFLAGS}
	cflags:			${CFLAGS}
	am_cflags:		${AM_CFLAGS}
	ldflags:		${LDFLAGS}
	am_ldflags:		${AM_LDFLAGS}
	libs:			${LIBS}
	defs:			${DEFS}
	static libraries:	${enable_static}
	shared libraries:	${enable_shared}
	ABI compatible:		${abi_compat}
	cunit:			${cunit_support}
	test_vald:		${test_vald}
	test_perf:		${test_perf}
	test_perf_proc:		${test_perf_proc}
	test_cpp:		${test_cpp}
	test_helper:		${test_helper}
	test_example:		${test_example}
	user_guides:		${user_guides}
])
