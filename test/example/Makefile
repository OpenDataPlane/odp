# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

ODP_ROOT = ../..
ODP_APP  = odp_example

include $(ODP_ROOT)/Makefile.inc
include ../Makefile.inc

.PHONY: default
default: $(OBJ_DIR) $(ODP_APP)

OBJS     =
OBJS    += $(OBJ_DIR)/odp_example.o

DEPS     = $(OBJS:.o=.d)

-include $(DEPS)


#
# Compile rules
#
$(OBJ_DIR)/%.o: %.c
	$(ECHO) Compiling $<
	$(CC) -c -MD $(EXTRA_CFLAGS) $(CFLAGS) -o $@ $<

#
# Link rule
#
$(ODP_APP): $(ODP_LIB) $(OBJS)
	$(ECHO) Linking $@
	$(CC) $(LDFLAGS) $(OBJS) $(ODP_LIB) $(STD_LIBS) -o $@

.PHONY: clean
clean:
	$(RMDIR) $(OBJ_DIR)
	$(RM) $(ODP_APP)
	$(MAKE) -C $(ODP_DIR) clean

.PHONY: install
install:
	install -d $(DESTDIR)/share/odp
	install -m 0755 $(ODP_APP) $(DESTDIR)/share/odp/
