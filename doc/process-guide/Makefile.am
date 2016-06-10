include ../Makefile.inc

IMAGES =   $(top_srcdir)/doc/images/aboutODP1.svg \
	   $(top_srcdir)/doc/images/aboutODP2.svg \
	   $(top_srcdir)/doc/images/aboutODP3.svg \
	   $(top_srcdir)/doc/images/packet_flow.svg \
	   $(top_srcdir)/doc/images/aboutODP5.svg \
	   $(top_srcdir)/doc/images/overview.svg

EXTRA_DIST = $(top_srcdir)/doc/process-guide/bylaws-guide.adoc \
	     $(top_srcdir)/doc/process-guide/release-guide.adoc \
	     $(top_srcdir)/doc/process-guide/faq.adoc \
	     $(top_srcdir)/CONTRIBUTING \
	     $(IMAGES)

all-local: bylaws-guide.html \
	   release-guide.html \
	   faq.html \
	   CONTRIBUTING.html

clean-local:
	rm -f $(builddir)/bylaws-guide.html
	rm -f $(builddir)/release-guide.html
	rm -f $(builddir)/faq.html
	rm -f $(builddir)/CONTRIBUTING.html

release-guide.html: $(top_srcdir)/doc/process-guide/release-guide.adoc \
		    $(top_srcdir)/doc/images/simple_release_git.svg \
		    $(top_srcdir)/doc/images/release_git.svg

bylaws-guide.html:  $(top_srcdir)/doc/process-guide/bylaws-guide.adoc

faq.html:  $(top_srcdir)/doc/process-guide/faq.adoc \
	   $(IMAGES)

#special case is not postfixed .adoc
CONTRIBUTING.html:  $(top_srcdir)/CONTRIBUTING
	asciidoctor $(ASCIIDOC_FLAGS) --out-file=$@ $<

#add deps on images

doc_DATA = bylaws-guide.html release-guide.html CONTRIBUTING.html faq.html
