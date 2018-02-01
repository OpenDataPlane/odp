AC_PREREQ([2.5])
##########################################################################
# Set correct API version
##########################################################################
m4_define([odpapi_generation_version], [1])
m4_define([odpapi_major_version], [15])
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
AM_INIT_AUTOMAKE([1.9 tar-pax subdir-objects foreign nostdinc])
AC_CONFIG_SRCDIR([include/odp/api/spec/init.h])
AM_CONFIG_HEADER([include/config.h])

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

ODP_LIBSO_VERSION=115:0:2
AC_SUBST(ODP_LIBSO_VERSION)

ODPHELPER_LIBSO_VERSION=112:1:0
AC_SUBST(ODPHELPER_LIBSO_VERSION)

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

AC_PROG_CXX

AC_PROG_INSTALL
AC_PROG_MAKE_SET

AC_PROG_LN_S

AM_PROG_AR
#Use libtool
LT_INIT([])
AC_SUBST([LIBTOOL_DEPS])
AM_PROG_LIBTOOL

PKG_PROG_PKG_CONFIG

# Checks for library functions.
dnl breaks cross-compilation and malloc(0) behaviour is not that important
dnl AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero clock_gettime gethostbyname getpagesize gettimeofday malloc memset munmap socket strchr strerror strrchr strstr strtoull])

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
AX_VALGRIND_DFLT([sgcheck], [off])
AX_VALGRIND_DFLT([helgrind], [off])
AX_VALGRIND_DFLT([drd], [off])
AX_VALGRIND_CHECK

##########################################################################
# Which architecture optimizations will we use
##########################################################################
AS_CASE([$host],
  [x86*], [ARCH_DIR=x86],
  [i686*], [ARCH_DIR=x86],
  [mips64*], [ARCH_DIR=mips64],
  [powerpc*], [ARCH_DIR=powerpc],
  [aarch64*], [ARCH_DIR=aarch64],
  [arm*], [ARCH_DIR=arm],
  [ARCH_DIR=undefined]
)
AC_SUBST([ARCH_DIR])

##########################################################################
# Warn on the defaults if arch is undefined
##########################################################################
if test "${ARCH_DIR}" = "undefined";
then
    echo "ARCH_DIR is undefined, please add your ARCH_DIR based on host=${host}"
    exit 1
fi

##########################################################################
# Architecture for ABI support
##########################################################################
AS_CASE([$host],
  [x86*],     [ARCH_ABI=x86_64-linux],
  [i686*],    [ARCH_ABI=x86_32-linux],
  [mips64*],  [ARCH_ABI=mips64-linux],
  [powerpc*], [ARCH_ABI=power64-linux],
  [aarch64*], [ARCH_ABI=arm64-linux],
  [arm*],     [ARCH_ABI=arm32-linux],
  [ARCH_ABI=undefined]
)
AC_SUBST([ARCH_ABI])

if test "${ARCH_ABI}" = "undefined";
then
    echo "ARCH_ABI is undefined, please add your ARCH_ABI based on host=${host}"
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
	[select platform to be used, default linux-dpdk])],
    [],
    [with_platform=linux-dpdk
    ])

AC_SUBST([with_platform])

##########################################################################
# Include m4 files
##########################################################################
m4_include([./doc/m4/configure.m4])
m4_include([./example/m4/configure.m4])
m4_include([./helper/m4/configure.m4])
m4_include([./test/m4/configure.m4])

##########################################################################
# Run platform specific checks and settings
##########################################################################
AS_IF([test "${with_platform}" = "linux-dpdk"],
      [m4_include([./platform/linux-dpdk/m4/configure.m4])],
      [AC_MSG_ERROR([UNSUPPORTED PLATFORM: ${with_platform}])])

AC_DEFINE_UNQUOTED([IMPLEMENTATION_NAME], ["$IMPLEMENTATION_NAME"],
		   [Define to the name of the implementation])

##########################################################################
# Set the install directory for test binaries/scripts
##########################################################################
AC_ARG_WITH([testdir],
    [AS_HELP_STRING([--with-testdir=DIR], [installation directory for tests])],
	[testdir=$withval],
	[testdir=no])
AS_IF([test "x$testdir" = "xyes"], [testdir=$libdir/odp/tests],
      [test "x$testdir" = "xno"], [testdir=])
AC_SUBST([testdir])
AM_CONDITIONAL([test_installdir], [test "x$testdir" != "xno"])

##########################################################################
# Set conditionals as computed within platform specific files
##########################################################################
AM_CONDITIONAL([HAVE_DOXYGEN], [test "x${DOXYGEN}" = "xdoxygen"])
AM_CONDITIONAL([user_guide], [test "x${user_guides}" = "xyes" ])
AM_CONDITIONAL([HAVE_MSCGEN], [test "x${MSCGEN}" = "xmscgen"])
AM_CONDITIONAL([helper_linux], [test x$helper_linux = xyes ])
AM_CONDITIONAL([ARCH_IS_ARM], [test "x${ARCH_DIR}" = "xarm"])
AM_CONDITIONAL([ARCH_IS_AARCH64], [test "x${ARCH_DIR}" = "xaarch64"])
AM_CONDITIONAL([ARCH_IS_MIPS64], [test "x${ARCH_DIR}" = "xmips64"])
AM_CONDITIONAL([ARCH_IS_POWERPC], [test "x${ARCH_DIR}" = "xpowerpc"])
AM_CONDITIONAL([ARCH_IS_X86], [test "x${ARCH_DIR}" = "xx86"])
AM_CONDITIONAL([ARCH_IS_X86_32], [test "x${ARCH_ABI}" = "xx86_32-linux"])
AM_CONDITIONAL([ARCH_IS_X86_64], [test "x${ARCH_ABI}" = "xx86_64-linux"])

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
# Enable/disable ODP_DEBUG
##########################################################################
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
		    [include additional debugging code ]
		    [(set to 'full' to enable all --enable-*-debug-* options)])])

AS_IF([test "x$enable_debug" != "xno"], [ODP_DEBUG=1],
      [ODP_DEBUG=0])
AC_DEFINE_UNQUOTED([ODP_DEBUG], [$ODP_DEBUG],
		   [Define to 1 to include additional debug code])

##########################################################################
# Enable/disable ODP_DEBUG_PRINT
##########################################################################
AC_ARG_ENABLE([debug-print],
    [AS_HELP_STRING([--enable-debug-print], [display debugging information])],
    [], [AS_IF([test "x$enable_debug" = "xfull"], [enable_debug_print=yes],
	       [enable_debug_print=no])])
AS_IF([test "x$enable_debug_print" != "xno"], [ODP_DEBUG_PRINT=1],
      [ODP_DEBUG_PRINT=0])
AC_DEFINE_UNQUOTED([ODP_DEBUG_PRINT], [$ODP_DEBUG_PRINT],
		   [Define to 1 to display debug information])

AC_ARG_ENABLE([helper-debug-print],
    [AS_HELP_STRING([--enable-helper-debug-print], [display helper debugging information])],
    [], [AS_IF([test "x$enable_debug" = "xfull"], [enable_helper_debug_print=yes],
	       [enable_helper_debug_print=no])])
AS_IF([test "x$enable_helper_debug_print" != "xno"], [ODPH_DEBUG_PRINT=1],
      [ODPH_DEBUG_PRINT=0])
AC_DEFINE_UNQUOTED([ODPH_DEBUG_PRINT], [$ODPH_DEBUG_PRINT],
		   [Define to 1 to display helper debug information])

##########################################################################
# Enable/disable ABI compatible build
##########################################################################
ODP_ABI_COMPAT=1
abi_compat=yes
AC_ARG_ENABLE([abi-compat],
    [  --disable-abi-compat    disables ABI compatible mode, enables inline code in header files],
    [if test "x$enableval" = "xno"; then
	ODP_ABI_COMPAT=0
	abi_compat=no
	#if there is no ABI compatibility the .so numbers are meaningless
	ODP_LIBSO_VERSION=0:0:0
    fi])
AC_SUBST(ODP_ABI_COMPAT)

##########################################################################
# Enable/disable deprecated API definitions
##########################################################################
ODP_DEPRECATED_API=0
deprecated=no
AC_ARG_ENABLE([deprecated],
    [  --enable-deprecated     enable deprecated API definitions],
    [if test "x$enableval" = "xyes"; then
	ODP_DEPRECATED_API=1
	deprecated=yes
    fi])
AC_SUBST(ODP_DEPRECATED_API)

##########################################################################
# Default warning setup
##########################################################################
ODP_CFLAGS="$ODP_CFLAGS -W -Wall -Werror"

dnl Use -Werror in the checks below since Clang emits a warning instead of
dnl an error when it encounters an unknown warning option.
AC_DEFUN([ODP_CHECK_CFLAG],
	 [AX_CHECK_COMPILE_FLAG([$1],
				[ODP_CFLAGS="$ODP_CFLAGS $1"],
				[], [-W -Wall -Werror],
				[AC_LANG_SOURCE([int main(void)
						{return 0;}])])])
ODP_CHECK_CFLAG([-Wstrict-prototypes])
ODP_CHECK_CFLAG([-Wmissing-prototypes])
ODP_CHECK_CFLAG([-Wmissing-declarations])
ODP_CHECK_CFLAG([-Wold-style-definition])
ODP_CHECK_CFLAG([-Wpointer-arith])
ODP_CHECK_CFLAG([-Wcast-align])
ODP_CHECK_CFLAG([-Wnested-externs])
ODP_CHECK_CFLAG([-Wcast-qual])
ODP_CHECK_CFLAG([-Wformat-nonliteral])
ODP_CHECK_CFLAG([-Wformat-security])
ODP_CHECK_CFLAG([-Wundef])
ODP_CHECK_CFLAG([-Wwrite-strings])
ODP_CHECK_CFLAG([-Wformat-truncation=0])
ODP_CHECK_CFLAG([-Wformat-overflow=0])

ODP_CFLAGS="$ODP_CFLAGS -std=c99"
ODP_CXXFLAGS="$ODP_CXXFLAGS -std=c++11"

# Extra flags for example to suppress certain warning types
ODP_CFLAGS="$ODP_CFLAGS $ODP_CFLAGS_EXTRA"

##########################################################################
# Check if compiler supports cmpxchng16 on x86-based architectures
##########################################################################
case "${host}" in
  i?86? | x86*)
  if test "${CC}" != "gcc" -o ${CC_VERSION_MAJOR} -ge 5; then
     ODP_CHECK_CFLAG([-mcx16])
  fi
  ;;
esac

##########################################################################
# Default include setup
##########################################################################
CFLAGS="$CFLAGS $ODP_CFLAGS"
CXXFLAGS="$CXXFLAGS $ODP_CXXFLAGS"

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([include/Makefile
		 include/odp/api/spec/version.h
		 include/odp/api/spec/deprecated.h])


##########################################################################
# distribute the changed variables among the Makefiles

AC_SUBST([LIBS])
AC_SUBST([CPPFLAGS])
AC_SUBST([CFLAGS])
AC_SUBST([LDFLAGS])
AC_SUBST([EXEEXT])

AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE $VERSION

	ODP Library version:	${ODP_LIBSO_VERSION}
	Helper Library version:	${ODPHELPER_LIBSO_VERSION}

	implementation_name:	${IMPLEMENTATION_NAME}
	host:			${host}
	ARCH_DIR		${ARCH_DIR}
	ARCH_ABI		${ARCH_ABI}
	with_platform:		${with_platform}
	helper_linux:		${helper_linux}
	prefix:			${prefix}
	sysconfdir:		${sysconfdir}
	libdir:			${libdir}
	includedir:		${includedir}
	testdir:		${testdir}
	WITH_ARCH:              ${WITH_ARCH}

	cc:			${CC}
	cc version:             ${CC_VERSION}
	cppflags:		${CPPFLAGS}
	cflags:			${CFLAGS}
	ldflags:		${LDFLAGS}
	libs:			${LIBS}
	defs:			${DEFS}
	static libraries:	${enable_static}
	shared libraries:	${enable_shared}
	ABI compatible:		${abi_compat}
	Deprecated APIs:	${deprecated}
	cunit:			${cunit_support}
	test_vald:		${test_vald}
	test_perf:		${test_perf}
	test_perf_proc:		${test_perf_proc}
	test_cpp:		${test_cpp}
	test_helper:		${test_helper}
	test_example:		${test_example}
	user_guides:		${user_guides}
])
