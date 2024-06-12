include $(top_srcdir)/example/Makefile.inc

LDADD += -lm

bin_PROGRAMS = model_explorer simple_linear mnist

simple_linear_SOURCES = simple_linear.c model_read.c model_read.h
model_explorer_SOURCES = model_explorer.c model_read.c model_read.h
mnist_SOURCES = mnist.c model_read.c model_read.h

EXTRA_DIST = \
	odp_ml_run_mnist.sh \
	example_digit.csv \
	mnist-12.onnx \
	odp_ml_run_model_explorer.sh \
	odp_ml_run_simple_linear.sh \
	simple_linear.onnx \
	odp_ml_run_conv.sh \
	conv.onnx \
	conv_gen.py \
	conv-input.bin \
	conv-output.bin \
	README.md

if test_example
TESTS = \
	odp_ml_run_mnist.sh \
	odp_ml_run_model_explorer.sh \
	odp_ml_run_simple_linear.sh \
	odp_ml_run_conv.sh
endif

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
