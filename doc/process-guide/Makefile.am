include ../Makefile.inc

EXTRA_DIST = $(top_srcdir)/doc/process-guide/bylaws-guide.adoc \
	     $(top_srcdir)/doc/process-guide/release-guide.adoc

all-local: bylaws-guide.html \
	   release-guide.html \
	   CONTRIBUTING.html

clean-local:
	rm -f $(builddir)/bylaws-guide.html
	rm -f $(builddir)/release-guide.html
	rm -f $(builddir)/CONTRIBUTING.html

release-guide.html: $(top_srcdir)/doc/process-guide/release-guide.adoc \
		    $(top_srcdir)/doc/images/simple_release_git.svg \
		    $(top_srcdir)/doc/images/release_git.svg

bylaws-guide.html:  $(top_srcdir)/doc/process-guide/bylaws-guide.adoc

#special case is not postfixed .adoc
CONTRIBUTING.html:  $(top_srcdir)/CONTRIBUTING
	asciidoctor $(ASCIIDOC_FLAGS) --out-file=$@ $<


doc_DATA = bylaws-guide.html release-guide.html CONTRIBUTING.html
