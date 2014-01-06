# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause


ODP_ROOT = .
ARCH     = linux-generic
ODP_LIB  = $(ODP_ROOT)/arch/$(ARCH)
OBJ_DIR  = ./obj
LIB      = $(ODP_LIB)/lib/odp.a
ODP_APP  = odp_app
ODP_TESTS = $(ODP_ROOT)/test
INCLUDE  = -I$(ODP_ROOT)/include
CC       ?= @gcc

.PHONY: all
all: libs tests

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
	$(MAKE) -C test install
