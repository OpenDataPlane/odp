# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause

.DEFAULT_GOAL := default

ODP_ROOT = .
ODP_APP  = odp_app
ODP_TESTS = $(ODP_ROOT)/test
INCLUDE  = -I$(ODP_ROOT)/include

include $(ODP_ROOT)/Makefile.inc

.PHONY: default
default: libs tests

.PHONY: all
all: libs tests docs

.PHONY: tests
tests:
	$(MAKE) -C $(ODP_TESTS)

.PHONY: docs
docs:
	$(MAKE) -C $(ODP_LIB) docs

.PHONY: libs
libs:
	$(MAKE) -C $(ODP_LIB) libs

.PHONY: clean
clean:
	$(MAKE) -C $(ODP_LIB) clean
	$(MAKE) -C $(ODP_TESTS) clean

.PHONY: install
install:
	$(MAKE) -C patform/$(platform) install
	$(MAKE) -C test install
