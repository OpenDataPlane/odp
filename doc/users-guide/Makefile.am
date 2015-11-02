TARGET = $(top_srcdir)/doc/output/users-guide.html

all-local: $(TARGET)

$(TARGET): users-guide.adoc
	@mkdir -p $(top_srcdir)/doc/output
	asciidoc --out-file=$@ $<

clean-local:
	rm -f $(TARGET)
