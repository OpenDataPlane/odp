# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

ODP_ROOT = ../..
ODP_APP  = odp_example

include ../Makefile.inc
include $(ODP_ROOT)/Makefile.inc

OBJS     =
OBJS    += $(OBJ_DIR)/odp_example.o

DEPS     = $(OBJS:.o=.d)

.PHONY: all
all: $(OBJ_DIR) $(ODP_APP)

-include $(DEPS)

$(DESTDIR)/lib/libodp.a:
	@test -e $@ || (echo "$@ is missing" && false)

$(OBJ_DIR): $(DESTDIR)/lib/libodp.a
	$(MKDIR) $(OBJ_DIR)

#
# Compile rules
#
$(OBJ_DIR)/%.o: %.c
	$(ECHO) Compiling $<
	$(CC) -c -MD $(EXTRA_CFLAGS) $(CFLAGS) -o $@ $<

#
# Link rule
#
$(ODP_APP): $(OBJS)
	$(ECHO) Linking $<
	$(CC) $(LDFLAGS) $(OBJS) $(LIB) -o $@

.PHONY: clean
clean:
	$(RMDIR) $(OBJ_DIR)
	$(RM) $(ODP_APP)

.PHONY: install
install:
	install -d $(DESTDIR)/share/odp
	install -m 0755 $(ODP_APP) $(DESTDIR)/share/odp/
