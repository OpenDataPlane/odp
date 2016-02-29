include ../Makefile.inc

SRC    = $(top_srcdir)/doc/implementers-guide/implementers-guide.adoc
TARGET = implementers-guide.html

EXTRA_DIST = $(SRC)

all-local: $(SRC)
	asciidoc $(ASCIIDOC_FLAGS) --out-file=$(TARGET) $(SRC)

clean-local:
	rm -f  $(builddir)/$(TARGET)
