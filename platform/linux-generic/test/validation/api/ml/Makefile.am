include ../Makefile.inc

test_PROGRAMS = ml_linux
ml_linux_SOURCES = ml_linux.c

EXTRA_DIST = \
	batch_add_gen.py \
	batch_add.onnx \
	gen_models.sh \
	README.md \
	requirements.txt \
	simple_linear_gen.py \
	simple_linear.onnx

# If building out-of-tree, make check will not copy the scripts and data to the
# $(builddir) assuming that all commands are run locally. However this prevents
# running tests on a remote target using LOG_COMPILER.
# So copy all script and data files explicitly here.
all-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(EXTRA_DIST); do \
			if [ -e $(srcdir)/$$f ]; then \
				mkdir -p $(builddir)/$$(dirname $$f); \
				cp -f $(srcdir)/$$f $(builddir)/$$f; \
			fi \
		done \
	fi

clean-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$f; \
		done \
	fi
