TARGET = $(top_srcdir)/doc/output/users-guide.html

all-local: $(TARGET)

$(TARGET): users-guide.adoc
	@mkdir -p $(top_srcdir)/doc/output
	asciidoc -b html5  -a icons -a toc2  -a max-width=55em --out-file=$@ $<

clean-local:
	rm -f $(TARGET)
