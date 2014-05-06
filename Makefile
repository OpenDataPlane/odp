# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause

.DEFAULT_GOAL := default

ODP_ROOT        = $(CURDIR)
ODP_TESTS       = $(ODP_ROOT)/test

include $(ODP_ROOT)/Makefile.inc

.PHONY: default
default: lib tests

.PHONY: all
all: tests_install docs_install

.PHONY: tests_install
tests_install: tests
	$(MAKE) -C test install

.PHONY: tests
tests: libs_install
	$(MAKE) -C $(ODP_TESTS)

.PHONY: docs
docs:
	$(MAKE) -C $(ODP_DIR) docs

.PHONY: docs_install
docs_install: docs
	$(MAKE) -C $(ODP_DIR) docs_install

.PHONY: lib
lib:
	$(MAKE) -C $(ODP_DIR) libs

.PHONY: clean
clean:
	$(MAKE) -C $(ODP_DIR) clean
	$(MAKE) -C $(ODP_TESTS) clean

.PHONY: libs_install
libs_install: lib
	$(MAKE) -C platform/$(PLATFORM) install

.PHONY: install
install: libs_install docs_install tests_install
