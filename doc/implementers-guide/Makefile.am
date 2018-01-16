include ../Makefile.inc

SRC    = implementers-guide.adoc
TARGET = implementers-guide.html
IMAGES = $(IMAGES_DIR)/abi_llvm.svg \
	 $(IMAGES_DIR)/abi_traditional.svg

EXTRA_DIST = $(SRC) $(IMAGES)

doc_DATA = $(TARGET)
$(TARGET): $(SRC) $(IMAGES)

CLEANFILES = $(doc_DATA)
