TARGET = $(top_srcdir)/doc/output/release-guide.html

EXTRA_DIST = release-guide.adoc

all-local: $(TARGET)

$(TARGET): release-guide.adoc
	@mkdir -p $(top_srcdir)/doc/output
	asciidoc -b html5  -a icons -a toc2  -a max-width=55em --out-file=$@ $<

clean-local:
	rm -f $(TARGET)
