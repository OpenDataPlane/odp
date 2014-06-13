# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

ODP_ROOT = ../..
ODP_APP  = odp_packet

include $(ODP_ROOT)/Makefile.inc
include ../Makefile.inc

OBJS     =
OBJS    += $(OBJ_DIR)/odp_example_pktio.o

DEPS     = $(OBJS:.o=.d)

.PHONY: default
default: $(OBJ_DIR) $(ODP_APP)

-include $(DEPS)

#
# Compile rules
#
$(OBJ_DIR)/%.o: %.c
	$(QUIET_CC)$(CC) -c -MD $(EXTRA_CFLAGS) $(CFLAGS) -o $@ $<

#
# Link rule
#
$(ODP_APP): $(ODP_LIB) $(OBJS)
	$(QUIET_LD)$(CC) $(LDFLAGS) $(OBJS) $(ODP_LIB) $(STD_LIBS) -o $@

.PHONY: clean
clean:
	$(Q)$(RMDIR) $(OBJ_DIR)
	$(Q)$(RM) $(ODP_APP)
	$(MAKE) -C $(ODP_DIR) clean

.PHONY: install
install:
	install -d $(DESTDIR)/share/odp
	install -m 0755 $(ODP_APP) $(DESTDIR)/share/odp/
