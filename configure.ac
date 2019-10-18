AC_PREREQ([2.5])
##########################################################################
# ODP API version
##########################################################################
m4_define([odpapi_generation_version], [1])
m4_define([odpapi_major_version], [22])
m4_define([odpapi_minor_version], [0])
m4_define([odpapi_point_version], [0])
m4_define([odpapi_version],
    [odpapi_generation_version.odpapi_major_version.odpapi_minor_version.odpapi_point_version])
AC_INIT([OpenDataPlane],[odpapi_version],[odp@lists.opendataplane.org])

ODP_VERSION_API_GENERATION=odpapi_generation_version
AC_SUBST(ODP_VERSION_API_GENERATION)
ODP_VERSION_API_MAJOR=odpapi_major_version
AC_SUBST(ODP_VERSION_API_MAJOR)
ODP_VERSION_API_MINOR=odpapi_minor_version
AC_SUBST(ODP_VERSION_API_MINOR)

##########################################################################
# Helper library version
##########################################################################
m4_define([odph_version_generation], [1])
m4_define([odph_version_major], [0])
m4_define([odph_version_minor], [3])

m4_define([odph_version],
    [odph_version_generation.odph_version_major.odph_version_minor])

ODPH_VERSION_GENERATION=odph_version_generation
AC_SUBST(ODPH_VERSION_GENERATION)
ODPH_VERSION_MAJOR=odph_version_major
AC_SUBST(ODPH_VERSION_MAJOR)
ODPH_VERSION_MINOR=odph_version_minor
AC_SUBST(ODPH_VERSION_MINOR)

##########################################################################
# Test if user has set CFLAGS. Automake initializes CFLAGS to "-g -O2"
# by default.
##########################################################################
AS_IF([test "$ac_cv_env_CFLAGS_set" = ""], [user_cflags=0], [user_cflags=1])

# Initialize automake
AM_INIT_AUTOMAKE([1.9 tar-pax subdir-objects foreign nostdinc -Wall -Werror])
AC_CONFIG_SRCDIR([include/odp/api/spec/init.h])
AM_CONFIG_HEADER([include/odp/autoheader_build.h include/odp/autoheader_external.h include/odp/autoheader_internal.h])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])

##########################################################################
# Set platform library version
#
# ODP does not promise backwards compatibility between releases, so we
# just enforce major:minor:release as version number.
##########################################################################

m4_define([odpso_version],
    [odpapi_generation_version[]odpapi_major_version:odpapi_minor_version:odpapi_point_version])

ODP_LIBSO_VERSION=odpso_version
AC_SUBST(ODP_LIBSO_VERSION)

ODPHELPER_LIBSO_VERSION=odpso_version
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

##########################################################################
# Default warning setup
##########################################################################
ODP_CFLAGS="$ODP_CFLAGS -W -Wall -Werror"
ODP_CXXFLAGS="$ODP_CXXFLAGS -W -Wall -Werror"

# Additional warnings:
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

# Suppressed warnings:
# GCC-9 warns about taking pointers to packed structure fields (e.g. protocol
# header structures). Generate only warnings on those, not errors.
ODP_CHECK_CFLAG([-Wno-error=address-of-packed-member])

ODP_CFLAGS="$ODP_CFLAGS -std=c99"
ODP_CXXFLAGS="$ODP_CXXFLAGS -std=c++11"

# Extra flags for example to suppress certain warning types
ODP_CFLAGS="$ODP_CFLAGS $ODP_CFLAGS_EXTRA"

##########################################################################
# Check if compiler supports cmpxchng16 on x86-based architectures
##########################################################################
ODP_CHECK_CFLAG([-mcx16])

##########################################################################
# Allow valgrind suite to run against the defined tests
##########################################################################
AX_VALGRIND_DFLT([sgcheck], [off])
AX_VALGRIND_DFLT([helgrind], [off])
AX_VALGRIND_DFLT([drd], [off])
AX_VALGRIND_CHECK

##########################################################################
# Architecture-specific dir
##########################################################################
AC_ARG_WITH([archincludedir],
	    [AS_HELP_STRING([--with-archincludedir=DIR],
	     [directory to hold arch-specific headers (${includedir})])],
	    [archincludedir=$with_archincludedir],
	    [archincludedir="${includedir}"])
AC_SUBST([archincludedir])

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
  [ARCH_DIR=default]
)
AC_SUBST([ARCH_DIR])

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
  [ARCH_ABI=default-linux]
)
AC_SUBST([ARCH_ABI])

AC_ARG_ENABLE([host-optimization],
	      [AS_HELP_STRING([--disable-host-optimization],
			      [disables using host-specific ARCH and ABI files])],
			      [], [enable_host_optimization=yes])
if test "x$enable_host_optimization" = "xno" ; then
	ARCH_DIR=default
	ARCH_ABI=default-linux
fi

##########################################################################
# Warn on the defaults if arch is undefined
##########################################################################
if test "${ARCH_DIR}" = "default";
then
    AC_MSG_WARN([ARCH_DIR is undefined, please add your ARCH_DIR based on host=${host}])
fi

if test "${ARCH_ABI}" = "default-linux";
then
    AC_MSG_WARN([ARCH_ABI is undefined, please add your ARCH_ABI based on host=${host}])
fi

##########################################################################
# Set correct pkgconfig version
##########################################################################
PKGCONFIG_VERSION=$(echo $VERSION | awk -F '.git' '{print $1}')
AC_SUBST(PKGCONFIG_VERSION)

##########################################################################
# Enable/disable ABI compatible build
##########################################################################
ODP_ABI_COMPAT=1
abi_compat=yes
AC_ARG_ENABLE([abi-compat],
    [AS_HELP_STRING([--disable-abi-compat],
		    [disables ABI compatible mode, enables inline code in header files])],
    [if test "x$enableval" = "xno"; then
	ODP_ABI_COMPAT=0
	abi_compat=no

	#if there is no ABI compatibility the .so numbers are meaningless
	ODP_LIBSO_VERSION=0:0:0

	# do not use -march=native with clang (due to possible failures on
	# clang optimizations) or when user have defined CFLAGS (may contain
	# another -march option).
	$CC --version | grep -q clang

	if test $? -ne 0 -a $user_cflags -eq 0; then
		ODP_CHECK_CFLAG([-march=native])
	fi
    fi])
AM_CONDITIONAL(ODP_ABI_COMPAT, [test "x$ODP_ABI_COMPAT" = "x1"])

##########################################################################
# Enable/disable link time optimization
##########################################################################
lto_enabled=no
AC_ARG_ENABLE([lto],
	[AS_HELP_STRING([--enable-lto],
			[Enable Link Time Optimization (LTO) in compiler and linker])],
	[if test "x$enableval" = "xyes"; then
		lto_enabled=yes
		# Fat LTO object file contains GIMPLE bytecodes and the usual
		# final code. There are less build problems (e.g. due to older
		# binutils), but object files are larger.
		ODP_LTO_FLAGS="-flto -ffat-lto-objects"
	fi])
AC_SUBST(ODP_LTO_FLAGS)

ODP_CFLAGS="$ODP_CFLAGS $ODP_LTO_FLAGS"

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

##########################################################################
# Run platform specific checks and settings
##########################################################################
AS_IF([test "${with_platform}" = "linux-generic"],
      [m4_include([./platform/linux-generic/m4/configure.m4])],
      [AC_MSG_ERROR([UNSUPPORTED PLATFORM: ${with_platform}])])

AC_DEFINE_UNQUOTED([_ODP_IMPLEMENTATION_NAME], ["$ODP_IMPLEMENTATION_NAME"],
		   [Define to the name of the implementation])

AM_CONDITIONAL([ODP_USE_CONFIG], [test "x$odp_use_config" = "xtrue"])

##########################################################################
# Build examples/tests dynamically
##########################################################################
AC_ARG_ENABLE([static-applications],
	      [AS_HELP_STRING([--disable-static-applications],
			      [disable static linking of examples and tests]
			      [ with ODP])], [],
	      [enable_static_applications=yes])
AS_IF([test "x$enable_static" != "xno" -a "x$enable_static_applications" != "xno"],
      [enable_static_applications=yes], [enable_static_applications=no])

AM_CONDITIONAL([STATIC_APPS], [test "x$enable_static_applications" != "xno"])
if test "x$DPDK_SHARED" = "xyes" -a "x$enable_static_applications" != "xno" ;
then
	AC_MSG_WARN([Static linking of examples and tests might fail when ]
	   [shared DPDK is detected. If build fails please retry with ]
	   [--disable-static-applications])
fi

##########################################################################
# Include m4 files
##########################################################################
m4_include([./doc/m4/configure.m4])
m4_include([./example/m4/configure.m4])
m4_include([./helper/m4/configure.m4])
m4_include([./test/m4/configure.m4])

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
AM_CONDITIONAL([ARCH_IS_DEFAULT], [test "x${ARCH_DIR}" = "xdefault"])
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
DX_ENV_APPEND(WITH_PLATFORM, $with_platform)

DX_INIT_DOXYGEN($PACKAGE_NAME,
		${srcdir}/doc/application-api-guide/Doxyfile,
		${builddir}/doc/application-api-guide/output,
		${srcdir}/doc/helper-guide/Doxyfile,
		${builddir}/doc/helper-guide/output,
		${srcdir}/doc/platform-api-guide/Doxyfile,
		${builddir}/doc/platform-api-guide/output)

##########################################################################
# Enable/disable ODP_DEBUG
##########################################################################
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
		    [include additional debugging code ]
		    [(set to 'full' to enable all --enable-*-debug-* options)])],
		    [], [enable_debug=no])

AS_IF([test "x$enable_debug" != "xno"], [ODP_DEBUG=1],
      [ODP_DEBUG=0])
AC_DEFINE_UNQUOTED([ODP_DEBUG], [$ODP_DEBUG],
		   [Define to 1 to include additional debug code])

AC_ARG_ENABLE([helper-debug],
    [AS_HELP_STRING([--enable-helper-debug], [helpers include additional debugging code])],
    [], [AS_IF([test "x$enable_debug" = "xfull"], [enable_helper_debug=yes],
    [enable_helper_debug=no])])
AS_IF([test "x$enable_helper_debug" != "xno"], [ODPH_DEBUG=1], [ODPH_DEBUG=0])
AC_DEFINE_UNQUOTED([ODPH_DEBUG], [$ODPH_DEBUG],
		   [Define to 1 to include additional helper debug code])

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

debug_settings="ODP_DEBUG=${ODP_DEBUG}, ODP_DEBUG_PRINT=${ODP_DEBUG_PRINT}, \
ODPH_DEBUG=${ODPH_DEBUG}, ODPH_DEBUG_PRINT=${ODPH_DEBUG_PRINT}"

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
# Default include setup
##########################################################################
CFLAGS="$CFLAGS $ODP_CFLAGS"
CXXFLAGS="$CXXFLAGS $ODP_CXXFLAGS"
LDFLAGS="$LDFLAGS $ODP_LTO_FLAGS"

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([include/Makefile
		 include/odp/api/spec/version.h
		 include/odp/api/spec/deprecated.h])

AC_CONFIG_FILES([helper/Makefile
		 helper/include/odp/helper/version.h])

##########################################################################
# distribute the changed variables among the Makefiles

AC_SUBST([LIBS])
AC_SUBST([CPPFLAGS])
AC_SUBST([CFLAGS])
AC_SUBST([LDFLAGS])
AC_SUBST([EXEEXT])

CC_VERSION=$($CC --version | head -n 1)

AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE $VERSION

	ODP Library version:	${ODP_LIBSO_VERSION}
	Helper Library version:	${ODPHELPER_LIBSO_VERSION}

	implementation_name:	${ODP_IMPLEMENTATION_NAME}
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
	with_openssl:           ${with_openssl}

	cc:			${CC}
	cc version:             ${CC_VERSION}
	cppflags:		${CPPFLAGS}
	cflags:			${CFLAGS}
	cxxflags:		${CXXFLAGS}
	ld:			${LD}
	ldflags:		${LDFLAGS}
	libs:			${LIBS}
	defs:			${DEFS}
	static libraries:	${enable_static}
	shared libraries:	${enable_shared}
	ABI compatible:		${abi_compat}
	link time optimization:	${lto_enabled}
	deprecated APIs:	${deprecated}
	debug:			${debug_settings}
	cunit:			${cunit_support}
	static tests linkage:	${enable_static_applications}
	with_examples:		${with_examples}
	with_tests:		${with_tests}
	test_vald:		${test_vald}
	test_perf:		${test_perf}
	test_cpp:		${test_cpp}
	test_helper:		${test_helper}
	test_example:		${test_example}
	user_guides:		${user_guides}
	pcapng:			${have_pcapng}
])

AS_IF([test "${with_openssl}" = "no"],
      [AC_MSG_WARN([Strong cryptography is not available without OpenSSL])]
      )
