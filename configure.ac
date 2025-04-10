AC_PREREQ([2.5])
##########################################################################
# ODP API version
##########################################################################
m4_define([odp_version_generation], [1])
m4_define([odp_version_major],     [47])
m4_define([odp_version_minor],      [0])
m4_define([odp_version_patch],      [0])

m4_define([odp_version_api],
    [odp_version_generation.odp_version_major.odp_version_minor])
m4_define([odp_version_library],
    [odp_version_generation.odp_version_major.odp_version_minor.odp_version_patch])

AC_INIT([OpenDataPlane],[odp_version_library],[odp@lists.opendataplane.org])

ODP_VERSION_API_GENERATION=odp_version_generation
AC_SUBST(ODP_VERSION_API_GENERATION)
ODP_VERSION_API_MAJOR=odp_version_major
AC_SUBST(ODP_VERSION_API_MAJOR)
ODP_VERSION_API_MINOR=odp_version_minor
AC_SUBST(ODP_VERSION_API_MINOR)
ODP_VERSION_API=odp_version_api
AC_SUBST(ODP_VERSION_API)

##########################################################################
# ODP Git Revision
##########################################################################
m4_define([odp_git_revision],
	[m4_esyscmd_s([sh -c 'hash=$(git rev-parse --short=8 HEAD 2>/dev/null) && echo "-$hash" || echo ""'])])

ODP_GIT_REVISION=odp_git_revision
AC_DEFINE_UNQUOTED([_ODP_GIT_REVISION], ["$ODP_GIT_REVISION"], "ODP Git Revision")

##########################################################################
# Helper library version
##########################################################################
m4_define([odph_version_generation], [1])
m4_define([odph_version_major], [7])
m4_define([odph_version_minor], [1])

m4_define([odph_version],
    [odph_version_generation.odph_version_major.odph_version_minor])

ODPH_VERSION_GENERATION=odph_version_generation
AC_SUBST(ODPH_VERSION_GENERATION)
ODPH_VERSION_MAJOR=odph_version_major
AC_SUBST(ODPH_VERSION_MAJOR)
ODPH_VERSION_MINOR=odph_version_minor
AC_SUBST(ODPH_VERSION_MINOR)
ODPH_VERSION=odph_version
AC_SUBST(ODPH_VERSION)

# Initialize automake
AM_INIT_AUTOMAKE([1.9 tar-pax subdir-objects foreign nostdinc -Wall -Werror])
AC_CONFIG_SRCDIR([include/odp/api/spec/init.h])
AC_CONFIG_HEADERS(m4_normalize([
	include/odp/autoheader_build.h
	include/odp/autoheader_external.h
	include/odp/autoheader_internal.h
	helper/include/odp/helper/autoheader_external.h
]))

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
    [odp_version_generation[]odp_version_major:odp_version_minor:odp_version_patch])

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
ODP_CHECK_CFLAG([-Wshadow=local])

# GCC 10 sometimes gets confused about object sizes and gives bogus warnings.
# Make the affected warnings generate only warnings, not errors.
AS_IF([test "$GCC" == yes],
      AS_IF([test `$CC -dumpversion | cut -d '.' -f 1` -ge 10],
	    ODP_CHECK_CFLAG([-Wno-error=array-bounds])
	    ODP_CHECK_CFLAG([-Wno-error=stringop-overflow])
	    ODP_CHECK_CXXFLAG([-Wno-error=stringop-overflow])
      )
)

ODP_CFLAGS="$ODP_CFLAGS -std=c11 -fno-strict-aliasing"
ODP_CXXFLAGS="$ODP_CXXFLAGS -std=c++11 -fno-strict-aliasing"

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
	     [directory to hold arch-specific headers [default=INCLUDEDIR]])],
	    [archincludedir=$with_archincludedir],
	    [archincludedir="${includedir}"])
AC_SUBST([archincludedir])

##########################################################################
# Which architecture optimizations will we use
##########################################################################
AS_CASE([$host],
  [x86*], [ARCH_DIR=x86],
  [i686*], [ARCH_DIR=x86],
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
  [powerpc*], [ARCH_ABI=power64-linux],
  [aarch64*], [ARCH_ABI=arm64-linux],
  [arm*],     [ARCH_ABI=arm32-linux],
  [ARCH_ABI=default-linux]
)
AC_SUBST([ARCH_ABI])

AC_ARG_ENABLE([host-optimization],
	      [AS_HELP_STRING([--disable-host-optimization],
			      [disables using host-specific ARCH and ABI files]
			      [[default=enabled]])],
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
ODP_ABI_COMPAT=0
abi_compat=no
AC_ARG_ENABLE([abi-compat],
    [AS_HELP_STRING([--enable-abi-compat],
		    [enables ABI compatible mode, disables inline code in header files]
		    [[default=disabled]])],
    [if test "x$enableval" = "xyes"; then
	ODP_ABI_COMPAT=1
	abi_compat=yes
    fi])
if test "x$abi_compat" = "xno" ; then
	# If there is no ABI compatibility the .so numbers are meaningless
	ODP_LIBSO_VERSION=0:0:0

	# Do not use -march=native with clang (due to possible failures on
	# clang optimizations).
	$CC --version | grep -q clang

	if test $? -ne 0; then
		ODP_CHECK_CFLAG([-march=native])
		ODP_CHECK_CXXFLAG([-march=native])
	fi
fi
AM_CONDITIONAL(ODP_ABI_COMPAT, [test "x$ODP_ABI_COMPAT" = "x1"])

##########################################################################
# Enable/disable link time optimization
##########################################################################
lto_enabled=no
AC_ARG_ENABLE([lto],
	[AS_HELP_STRING([--enable-lto],
			[Enable Link Time Optimization (LTO) in compiler and linker]
			[[default=disabled]])],
	[if test "x$enableval" = "xyes"; then
		lto_enabled=yes
		# Fat LTO object file contains GIMPLE bytecodes and the usual
		# final code. There are less build problems (e.g. due to older
		# binutils), but object files are larger.
		#
		# -flto=auto and -ffat-lto-objects are currently not supported by clang.
		$CC --version | grep -q clang
		if test $? -ne 0; then
			ODP_LTO_FLAGS="-flto=auto -ffat-lto-objects"
		else
			ODP_LTO_FLAGS="-flto"
		fi
	fi])

ODP_CFLAGS="$ODP_CFLAGS $ODP_LTO_FLAGS"
ODP_LDFLAGS="$ODP_LDFLAGS $ODP_LTO_FLAGS"

##########################################################################
# Build examples/tests dynamically
##########################################################################
AC_ARG_ENABLE([static-applications],
	      [AS_HELP_STRING([--disable-static-applications],
			      [disable static linking of examples and tests]
			      [with ODP [default=enabled]])], [],
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
    [AS_HELP_STRING([--with-testdir[=DIR]],
		    [installation directory for tests [default=none]])],
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
AM_CONDITIONAL([helper_cli], [test x$helper_cli = xyes ])
AM_CONDITIONAL([ARCH_IS_ARM], [test "x${ARCH_DIR}" = "xarm"])
AM_CONDITIONAL([ARCH_IS_AARCH64], [test "x${ARCH_DIR}" = "xaarch64"])
AM_CONDITIONAL([ARCH_IS_DEFAULT], [test "x${ARCH_DIR}" = "xdefault"])
AM_CONDITIONAL([ARCH_IS_POWERPC], [test "x${ARCH_DIR}" = "xpowerpc"])
AM_CONDITIONAL([ARCH_IS_X86], [test "x${ARCH_DIR}" = "xx86"])
AM_CONDITIONAL([ARCH_IS_X86_32], [test "x${ARCH_ABI}" = "xx86_32-linux"])
AM_CONDITIONAL([ARCH_IS_X86_64], [test "x${ARCH_ABI}" = "xx86_64-linux"])

##########################################################################
# Enable/disable ODP_DEBUG
##########################################################################
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
		    [include additional debugging code.]
		    [Set to 'full' to enable all --enable-*-debug-* options]
		    [[default=disabled]])],
		    [], [enable_debug=no])

AS_IF([test "x$enable_debug" != "xno"], [ODP_DEBUG=1],
      [ODP_DEBUG=0])
AC_DEFINE_UNQUOTED([ODP_DEBUG], [$ODP_DEBUG],
		   [Define to 1 to include additional debug code])

##########################################################################
# Enable/disable ODP_DEBUG_PRINT
##########################################################################
AC_ARG_ENABLE([debug-print],
    [AS_HELP_STRING([--enable-debug-print],
		    [display debugging information [default=disabled]])],
    [], [AS_IF([test "x$enable_debug" = "xfull"], [enable_debug_print=yes],
	       [enable_debug_print=no])])
AS_IF([test "x$enable_debug_print" != "xno"], [ODP_DEBUG_PRINT=1],
      [ODP_DEBUG_PRINT=0])
AC_DEFINE_UNQUOTED([ODP_DEBUG_PRINT], [$ODP_DEBUG_PRINT],
		   [Define to 1 to display debug information])

debug_settings="ODP_DEBUG=${ODP_DEBUG}, ODP_DEBUG_PRINT=${ODP_DEBUG_PRINT}, \
ODPH_DEBUG=${ODPH_DEBUG}, ODPH_DEBUG_PRINT=${ODPH_DEBUG_PRINT}"

##########################################################################
# Enable/disable deprecated API definitions
##########################################################################
ODP_DEPRECATED_API=0
deprecated=no
AC_ARG_ENABLE([deprecated],
    [AS_HELP_STRING([--enable-deprecated],
		    [enable deprecated API definitions [default=disabled]])],
    [if test "x$enableval" = "xyes"; then
	ODP_DEPRECATED_API=1
	deprecated=yes
    fi])
AC_SUBST(ODP_DEPRECATED_API)

##########################################################################
# Determine which platform to build for
##########################################################################
AC_ARG_WITH([platform],
    [AS_HELP_STRING([--with-platform=platform],
	[select platform to be used [default=linux-generic]])],
    [],
    [with_platform=linux-generic
    ])

AC_SUBST([with_platform])

##########################################################################
# Run platform specific checks and settings
##########################################################################
# Placeholder for platform dependency libraries which might come from custom
# paths. Platform should fill it in configure.m4 with AS_VAR_APPEND.
# This works around a bug in libtool.m4 on some systems:
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=297726
PLAT_DEP_LIBS=
AC_SUBST([PLAT_DEP_LIBS])
# Platforms should append to this variable to have their settings printed
# at the end of the configure report.
PLAT_CFG_TEXT="
	Platform specific:"

AS_IF([test "${with_platform}" = "linux-generic"],
      [m4_include([./platform/linux-generic/m4/configure.m4])],
      [AC_MSG_ERROR([UNSUPPORTED PLATFORM: ${with_platform}])])

AC_DEFINE_UNQUOTED([_ODP_IMPLEMENTATION_NAME], ["$ODP_IMPLEMENTATION_NAME"],
		   [Define to the name of the implementation])

AM_CONDITIONAL([ODP_USE_CONFIG], [test "x$odp_use_config" = "xtrue"])
AC_SUBST([ODP_LIB_NAME])

##########################################################################
# Setup doxygen documentation
##########################################################################
DX_HTML_FEATURE(ON)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_DOT_FEATURE(ON)
DX_ENV_APPEND(WITH_PLATFORM, $with_platform)

DX_INIT_DOXYGEN($PACKAGE_NAME,
		${srcdir}/doc/application-api-guide/Doxyfile,
		${builddir}/doc/application-api-guide/output,
		${srcdir}/doc/helper-guide/Doxyfile,
		${builddir}/doc/helper-guide/output,
		${srcdir}/doc/platform-api-guide/Doxyfile,
		${builddir}/doc/platform-api-guide/output)

##########################################################################
# Default include setup
##########################################################################
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([include/Makefile
		 include/odp/api/spec/version.h
		 include/odp/api/spec/deprecated.h])

AC_CONFIG_FILES([helper/Makefile
		 helper/include/odp/helper/version.h])

##########################################################################
# distribute the changed variables among the Makefiles

AC_SUBST([ODP_CFLAGS])
AC_SUBST([ODP_CXXFLAGS])
AC_SUBST([ODP_LDFLAGS])

AC_SUBST([EXEEXT])

AM_CONDITIONAL([enable_static], [test x$enable_static = xyes ])
AM_CONDITIONAL([enable_shared], [test x$enable_shared = xyes ])

AM_CONDITIONAL([cross_compile], [test x$host != x -a x$host != x$build ])

CC_VERSION=$($CC --version | head -n 1)

AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE $VERSION

	ODP API version:	${ODP_VERSION_API}
	ODP Library name:	${ODP_LIB_NAME}
	ODP Library version:	${ODP_LIBSO_VERSION}
	Helper version:		${ODPH_VERSION}

	implementation_name:	${ODP_IMPLEMENTATION_NAME}
	build:			${build}
	host:			${host}
	ARCH_DIR		${ARCH_DIR}
	ARCH_ABI		${ARCH_ABI}
	with_platform:		${with_platform}
	helper_linux:		${helper_linux}
	helper_cli:		${helper_cli}
	prefix:			${prefix}
	sysconfdir:		${sysconfdir}
	libdir:			${libdir}
	includedir:		${includedir}
	testdir:		${testdir}

	cc:			${CC}
	cc version:             ${CC_VERSION}
	cppflags:		${CPPFLAGS}
	cflags:			${ODP_CFLAGS} ${CFLAGS}
	cxxflags:		${ODP_CXXFLAGS} ${CXXFLAGS}
	ld:			${LD}
	ldflags:		${ODP_LDFLAGS} ${LDFLAGS}
	libs:			${LIBS}
	dependency libs:	${PLAT_DEP_LIBS}
	defs:			${DEFS}
	static libraries:	${enable_static}
	shared libraries:	${enable_shared}
	ABI compatible:		${abi_compat}
	link time optimization:	${lto_enabled}
	deprecated APIs:	${deprecated}
	deprecated helper APIs:	${enable_helper_deprecated}
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
${PLAT_CFG_TEXT}
])
