##
## Copyright (c) 2013, Linaro Limited
## All rights reserved.
##
## SPDX-License-Identifier:     BSD-3-Clause
##

.DEFAULT_GOAL := libs

ODP_ROOT = ../..
LIB_DIR  = ./lib
DOC_DIR  = ./doc

LINUX_GENERIC_DIR = ../linux-generic

EXTRA_CFLAGS  += -I./include
EXTRA_CFLAGS  += -I./include/api
EXTRA_CFLAGS  += -I$(LINUX_GENERIC_DIR)/include
EXTRA_CFLAGS  += -I$(LINUX_GENERIC_DIR)/include/api
EXTRA_CFLAGS  += -I$(ODP_ROOT)/include

include $(ODP_ROOT)/Makefile.inc
STATIC_LIB = ./lib/libodp.a

#
# Object files
#
OBJS     =
OBJS    += $(OBJ_DIR)/odp_barrier.o
OBJS    += $(OBJ_DIR)/odp_buffer.o
OBJS    += $(OBJ_DIR)/odp_buffer_pool.o
OBJS    += $(OBJ_DIR)/odp_coremask.o
OBJS    += $(OBJ_DIR)/odp_init.o
OBJS    += $(OBJ_DIR)/odp_linux.o
OBJS    += $(OBJ_DIR)/odp_packet.o
OBJS    += $(OBJ_DIR)/odp_packet_flags.o
OBJS    += $(OBJ_DIR)/odp_packet_io.o
OBJS    += $(OBJ_DIR)/odp_packet_socket.o
OBJS    += $(OBJ_DIR)/odp_queue.o
OBJS    += $(OBJ_DIR)/odp_schedule.o
OBJS    += $(OBJ_DIR)/odp_shared_memory.o
OBJS    += $(OBJ_DIR)/odp_spinlock.o
OBJS    += $(OBJ_DIR)/odp_system_info.o
OBJS    += $(OBJ_DIR)/odp_thread.o
OBJS    += $(OBJ_DIR)/odp_ticketlock.o
OBJS    += $(OBJ_DIR)/odp_time.o
OBJS    += $(OBJ_DIR)/odp_timer.o
OBJS    += $(OBJ_DIR)/odp_ring.o
OBJS    += $(OBJ_DIR)/odp_rwlock.o

DEPS     = $(OBJS:.o=.d)

.PHONY: all
all: libs

-include $(DEPS)

$(LIB_DIR):
	$(MKDIR) $(LIB_DIR)

#
# Compile rules
#
vpath %.c source:$(LINUX_GENERIC_DIR)/source

$(OBJ_DIR)/%.o: %.c
	$(ECHO) "  CC    $<"
	$(CC) -c -MD $(EXTRA_CFLAGS) $(CFLAGS) -o $@ $<

#
# Lib rule
#
$(STATIC_LIB): $(OBJS)
	$(AR) -cr $@ $(OBJS)

clean:
	$(RMDIR) $(OBJ_DIR)
	$(RMDIR) $(LIB_DIR)

.PHONY: docs
docs:
	$(ECHO) "Documenation is not yet available"
	@false

.PHONY: libs
libs: $(OBJ_DIR) $(LIB_DIR) $(STATIC_LIB)

.PHONY: lib_install
lib_install: libs
	install -d $(DESTDIR)/lib
	install -m 0644 ${STATIC_LIB} $(DESTDIR)/lib/

.PHONY: headers_install
headers_install: libs
	$(ECHO) Installing headers to $(DESTDIR)/include
	$(COPY) $(ODP_ROOT)/include $(DESTDIR)
	$(COPY) $(LINUX_GENERIC_DIR)/include/api/* $(DESTDIR)/include/
	-$(COPY) include/api/* $(DESTDIR)/include/

install: lib_install headers_install
