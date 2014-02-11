# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

ODP_ROOT = ../..
ODP_APP  = odp_packet

CFLAGS  += -I.
CFLAGS  += -I$(ARCH_INC)
CFLAGS  += -DODP_HAVE_NETMAP
CFLAGS  += -O0 -g

include $(ODP_ROOT)/Makefile.inc

LDFLAGS += -lrt
LDFLAGS += $(EXTRA_CFLAGS)

OBJS     =
OBJS    += $(OBJ_DIR)/odp_example_pktio_netmap.o

DEPS     = $(OBJS:.o=.d)

.PHONY: all
all: $(OBJ_DIR) $(ODP_APP)

-include $(DEPS)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(LIB):
	@echo Building $@
	$(MAKE) -C $(ODP_LIB) libs

#
# Compile rules
#
$(OBJ_DIR)/%.o: %.c
	@echo Compiling $<
	$(CC) -c -MD $(CFLAGS) -o $@ $<

#
# Link rule
#
$(ODP_APP): $(LIB) $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIB) -o $@

.PHONY: libs
libs:
	$(MAKE) -C $(ODP_LIB) libs

.PHONY: docs
docs:
	$(MAKE) -C $(ODP_LIB) docs

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR)
	rm -f $(ODP_APP)
	$(MAKE) -C $(ODP_LIB) clean

.PHONY: install
install:
	install -d $(DESTDIR)$(prefix)/usr/local/share/odp
	install -m 0755 $(ODP_APP) $(DESTDIR)$(prefix)/usr/local/share/odp/
