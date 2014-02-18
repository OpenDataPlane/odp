# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

ODP_ROOT = ../..

#
# API testing stuffs
#
ODP_ATOMIC    = odp_atomic
ODP_SHM       = odp_shm
ODP_RING      = odp_ring

EXTRA_CFLAGS  += -I$(ODP_ROOT)/platform/linux-generic/include

include $(ODP_ROOT)/Makefile.inc
include ../Makefile.inc

.PHONY: default
default: all

EXTRA_CFLAGS  += -I.

ATOMIC_OBJS  =
ATOMIC_OBJS += $(OBJ_DIR)/odp_common.o
ATOMIC_OBJS += $(OBJ_DIR)/odp_atomic_test.o

SHM_OBJS  =
SHM_OBJS += $(OBJ_DIR)/odp_common.o
SHM_OBJS += $(OBJ_DIR)/odp_shm_test.o

RING_OBJS  =
RING_OBJS += $(OBJ_DIR)/odp_common.o
RING_OBJS += $(OBJ_DIR)/odp_ring_test.o

DEPS     = $(ATOMIC_OBJS:.o=.d) $(SHM_OBJS:.o=.d) $(RING_OBJS:.o=.d)

.PHONY: all
all: $(OBJ_DIR) $(ODP_ATOMIC) $(ODP_SHM) $(ODP_RING)
atomic: $(OBJ_DIR) $(ODP_ATOMIC)
shm: $(OBJ_DIR) $(ODP_SHM)
ring: $(OBJ_DIR) $(ODP_RING)

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
$(ODP_ATOMIC): $(ODP_LIB) $(ATOMIC_OBJS)
	$(ECHO) Linking $<
	$(CC) $(LDFLAGS) $(ATOMIC_OBJS) $(ODP_LIB) -o $@

$(ODP_SHM): $(ODP_LIB) $(SHM_OBJS)
	$(ECHO) Linking $<
	$(CC) $(LDFLAGS) $(SHM_OBJS) $(ODP_LIB) -o $@

$(ODP_RING): $(ODP_LIB) $(RING_OBJS)
	$(ECHO) Linking $<
	$(CC) $(LDFLAGS) $(RING_OBJS) $(ODP_LIB) -o $@

.PHONY: clean
clean:
	$(RMDIR) $(OBJ_DIR)
	$(RM) $(ODP_ATOMIC)
	$(RM) $(ODP_SHM)
	$(RM) $(ODP_RING)
	$(MAKE) -C $(ODP_DIR) clean

.PHONY: install
install:
	install -d $(DESTDIR)/share/odp
	install -m 0755 $(ODP_ATOMIC) $(DESTDIR)/share/odp/
	install -m 0755 $(ODP_SHM) $(DESTDIR)/share/odp/
	install -m 0755 $(ODP_RING) $(DESTDIR)/share/odp/
