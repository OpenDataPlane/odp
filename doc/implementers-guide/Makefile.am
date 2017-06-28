include ../Makefile.inc

SRC    = implementers-guide.adoc
TARGET = implementers-guide.html

EXTRA_DIST = $(SRC)

doc_DATA = $(TARGET)
$(TARGET): $(SRC)

clean-local:
	rm -f  $(builddir)/$(TARGET)
