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

CFLAGS  += -I.
CFLAGS  += -I$(ODP_LIB)
CFLAGS  += -I$(ODP_ROOT)/platform/linux-generic/include
CFLAGS  += -I$(ARCH_INC)
#CFLAGS  += -DODP_TEST_ATOMIC

include $(ODP_ROOT)/Makefile.inc

LDFLAGS += -lrt
LDFLAGS += $(EXTRA_CFLAGS)

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
$(ODP_ATOMIC): $(LIB) $(ATOMIC_OBJS)
	$(CC) $(LDFLAGS) $(ATOMIC_OBJS) $(LIB) -o $@

$(ODP_SHM): $(LIB) $(SHM_OBJS)
	$(CC) $(LDFLAGS) $(SHM_OBJS) $(LIB) -o $@

$(ODP_RING): $(LIB) $(RING_OBJS)
	$(CC) $(LDFLAGS) $(RING_OBJS) $(LIB) -o $@

.PHONY: libs
libs:
	$(MAKE) -C $(ODP_LIB) libs

.PHONY: docs
docs:
	$(MAKE) -C $(ODP_LIB) docs

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR)
	rm -f $(ODP_ATOMIC)
	rm -f $(ODP_SHM)
	rm -f $(ODP_RING)
	$(MAKE) -C $(ODP_LIB) clean

.PHONY: install
install:
	install -d $(DESTDIR)$(prefix)/usr/local/share/odp
	install -m 0755 $(ODP_ATOMIC) $(DESTDIR)$(prefix)/usr/local/share/odp/
	install -m 0755 $(ODP_SHM) $(DESTDIR)$(prefix)/usr/local/share/odp/
	install -m 0755 $(ODP_RING) $(DESTDIR)$(prefix)/usr/local/share/odp/
