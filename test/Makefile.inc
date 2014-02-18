# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause

ifdef DESTDIR

ODP_LIB = $(DESTDIR)/lib/libodp.a
EXTRA_CFLAGS += -I$(DESTDIR)/include
EXTRA_CFLAGS += -I$(DESTDIR)/include/api

else

ODP_LIB = $(ODP_DIR)/lib/libodp.a
EXTRA_CFLAGS += -I$(ODP_ROOT)/include
EXTRA_CFLAGS += -I$(ODP_DIR)/include/api

$(ODP_LIB):
	@echo Building $@
	$(MAKE) -C $(ODP_DIR) libs
endif
