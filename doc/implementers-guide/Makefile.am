TARGET = $(top_srcdir)/doc/output/implementers-guide.html

all-local: $(TARGET)

$(TARGET): implementers-guide.adoc
	@mkdir -p $(top_srcdir)/doc/output
	asciidoc --out-file=$@ $<

clean-local:
	rm -f $(TARGET)
