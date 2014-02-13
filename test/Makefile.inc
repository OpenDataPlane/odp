# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause

ODP_TEST_ROOT = $(ODP_ROOT)/test

CFLAGS += -I$(DESTDIR)/include
LIB = -L$(DESTDIR)/lib -lodp

LDFLAGS += -lrt
LDFLAGS += $(EXTRA_CFLAGS)
