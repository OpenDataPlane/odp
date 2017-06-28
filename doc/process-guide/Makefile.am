include ../Makefile.inc

IMAGES =   $(IMAGES_DIR)/aboutODP1.svg \
	   $(IMAGES_DIR)/aboutODP2.svg \
	   $(IMAGES_DIR)/aboutODP3.svg \
	   $(IMAGES_DIR)/packet_flow.svg \
	   $(IMAGES_DIR)/aboutODP5.svg \
	   $(IMAGES_DIR)/overview.svg

EXTRA_DIST = bylaws-guide.adoc \
	     release-guide.adoc \
	     faq.adoc \
	     $(top_srcdir)/CONTRIBUTING \
	     $(IMAGES)

all-local: bylaws-guide.html \
	   release-guide.html \
	   faq.html \
	   CONTRIBUTING.html \
	   CHANGELOG.html

clean-local:
	rm -f $(builddir)/bylaws-guide.html
	rm -f $(builddir)/release-guide.html
	rm -f $(builddir)/faq.html
	rm -f $(builddir)/CONTRIBUTING.html
	rm -f $(builddir)/CHANGELOG.html

release-guide.html: release-guide.adoc \
		    $(IMAGES_DIR)/simple_release_git.svg \
		    $(IMAGES_DIR)/release_git.svg

bylaws-guide.html:  bylaws-guide.adoc

faq.html:  faq.adoc \
	   $(IMAGES)

#special case is not postfixed .adoc
CONTRIBUTING.html:  $(top_srcdir)/CONTRIBUTING
	asciidoctor $(ASCIIDOC_FLAGS) --out-file=$@ $<

CHANGELOG.html:  $(top_srcdir)/CHANGELOG
	asciidoctor $(ASCIIDOC_FLAGS) --out-file=$@ $<

#add deps on images

doc_DATA = bylaws-guide.html release-guide.html CONTRIBUTING.html faq.html CHANGELOG.html
