dnl Use -Werror in the checks below since Clang emits a warning instead of
dnl an error when it encounters an unknown warning option.

# ODP_CHECK_CFLAG(FLAG)
# ---------------------
# Add FLAG to ODP_CFLAGS if compiler supports that option
AC_DEFUN([ODP_CHECK_CFLAG],
	 [AC_LANG_PUSH([C])
	  AX_CHECK_COMPILE_FLAG([$1],
				[ODP_CFLAGS="$ODP_CFLAGS $1"],
				[], [-W -Wall -Werror],
				[AC_LANG_SOURCE([int main(void)
						{return 0;}])])
	  AC_LANG_POP([C])])

# ODP_CHECK_CXXFLAG(FLAG)
# ---------------------
# Add FLAG to ODP_CFLAGS if compiler supports that option
AC_DEFUN([ODP_CHECK_CXXFLAG],
	 [AC_LANG_PUSH([C++])
	  AX_CHECK_COMPILE_FLAG([$1],
				[ODP_CXXFLAGS="$ODP_CXXFLAGS $1"],
				[], [-W -Wall -Werror],
				[AC_LANG_SOURCE([int main(void)
						{return 0;}])])
	  AC_LANG_POP([C++])])
