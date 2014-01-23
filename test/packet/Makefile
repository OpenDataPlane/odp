# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause



ODP_ROOT = ../..
ARCH     = linux-generic
ODP_LIB  = $(ODP_ROOT)/arch/$(ARCH)
ODP_INC  = $(ODP_ROOT)/include
OBJ_DIR  = ./obj
LIB      = $(ODP_LIB)/lib/odp.a
ODP_APP  = odp_packet

CC       ?= @gcc



E_FLAGS  = -W -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
E_FLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith
E_FLAGS += -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral
E_FLAGS += -Wformat-security -Wundef -Wwrite-strings

CFLAGS  += -pthread
CFLAGS  += -I.
CFLAGS  += -I$(ODP_INC)
CFLAGS  += $(E_FLAGS)
CFLAGS  += $(EXTRA_CFLAGS)

LDFLAGS += -pthread
LDFLAGS += -lrt
LDFLAGS += $(EXTRA_CFLAGS)

OBJS     =
OBJS    += $(OBJ_DIR)/odp_example_pktio.o

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
	install -d $(DESTDIR)$(prefix)/lib
	install -m 0644 ${LIB} $(DESTDIR)$(prefix)/lib/
	install -d $(DESTDIR)$(prefix)/share/odp
	install -m 0755 $(ODP_APP) $(DESTDIR)$(prefix)/share/odp/
