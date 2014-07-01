ACLOCAL_AMFLAGS=-I m4
AUTOMAKE_OPTIONS = foreign

SUBDIRS = platform test

include $(top_srcdir)/aminclude.am

EXTRA_DIST = bootstrap $(DX_CONFIG)

clean-local:
	rm -rf $(top_builddir)/doxygen-doc
