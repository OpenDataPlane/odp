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

CFLAGS  += -I$(ODP_ROOT)/platform/linux-generic/include

include ../Makefile.inc
include $(ODP_ROOT)/Makefile.inc

CFLAGS      += -I$(ODP_TEST_ROOT)/api_test

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

$(OBJ_DIR):
	$(MKDIR) $(OBJ_DIR)

#
# Compile rules
#
$(OBJ_DIR)/%.o: %.c
	$(ECHO) Compiling $<
	$(CC) -c -MD $(CFLAGS) -o $@ $<

#
# Link rule
#
$(ODP_ATOMIC): $(ATOMIC_OBJS)
	$(CC) $(LDFLAGS) $(ATOMIC_OBJS) $(LIB) -o $@

$(ODP_SHM): $(SHM_OBJS)
	$(CC) $(LDFLAGS) $(SHM_OBJS) $(LIB) -o $@

$(ODP_RING): $(RING_OBJS)
	$(CC) $(LDFLAGS) $(RING_OBJS) $(LIB) -o $@

.PHONY: clean
clean:
	$(RMDIR) $(OBJ_DIR)
	$(RM) $(ODP_ATOMIC)
	$(RM) $(ODP_SHM)
	$(RM) $(ODP_RING)

.PHONY: install
install:
	install -d $(DESTDIR)/share/odp
	install -m 0755 $(ODP_ATOMIC) $(DESTDIR)/share/odp/
	install -m 0755 $(ODP_SHM) $(DESTDIR)/share/odp/
	install -m 0755 $(ODP_RING) $(DESTDIR)/share/odp/
