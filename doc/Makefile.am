if HAVE_DOXYGEN

noinst_docdatadir = ${datadir}/doc
noinst_imagedir = ${datadir}/doc/images
noinst_usersguidedir = ${datadir}/doc/users-guide

noinst_docdata_DATA = \
		$(srcdir)/doxygen.cfg \
		$(srcdir)/odp.dox \
		$(srcdir)/odpdoxygen.css

noinst_image_DATA = \
		$(srcdir)/images/ODP-Logo-HQ.png \
		$(srcdir)/images/overview.eps \
		$(srcdir)/images/overview.png

noinst_usersguide_DATA = \
		$(srcdir)/users-guide/guide.dox

dist_noinst_docdata_DATA = ${noinst_docdata_DATA}
dist_noinst_image_DATA = ${noinst_image_DATA}
dist_noinst_usersguide_DATA = ${noinst_usersguide_DATA}

clean-local:
	rm -rf $(DX_DOCDIR)
endif
