ACLOCAL_AMFLAGS=-I m4
AM_DISTCHECK_CONFIGURE_FLAGS = --enable-test-cpp	\
			       --enable-test-example	\
			       --enable-test-helper	\
			       --enable-test-perf	\
			       --enable-test-perf-proc	\
			       --enable-test-vald	\
			       --enable-user-guides	\
			       --with-testdir

#@with_platform@ works alone in subdir but not as part of a path???
SUBDIRS = @platform_with_platform@ \
	  helper \
	  helper/test \
	  doc \
	  example . \
	  test

@DX_RULES@

EXTRA_DIST = bootstrap $(DX_CONFIG) CHANGELOG config/README
