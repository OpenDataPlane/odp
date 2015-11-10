ACLOCAL_AMFLAGS=-I m4
AUTOMAKE_OPTIONS = foreign

#@with_platform@ works alone in subdir but not as part of a path???
SUBDIRS = @platform_with_platform@ \
	  helper \
	  test \
	  @platform_with_platform_test@ \
	  helper/test \
	  doc \
	  example \
	  scripts

include $(top_srcdir)/aminclude.am

EXTRA_DIST = bootstrap $(DX_CONFIG) config/README .scmversion
