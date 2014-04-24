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

MY_PLATFORM  = DEVICE_K2K

PLAT_CFLAGS  = -D$(MY_PLATFORM)
PLAT_CFLAGS += -D_GNU_SOURCE -DEM_32_BIT -DTI_EM_CENTRAL_SCHED
PLAT_CFLAGS += -DTI_EM_TRACE_LEVEL=3 -DEM_CHECK_LEVEL=1
PLAT_CFLAGS += -DTI_EM_LINUX -DTI_EM_GCC -DTI_EM_ARM_A15 -DTI_EM_C6638
PLAT_CFLAGS += -D_LITTLE_ENDIAN -DTI_EM_USE_MSM -DTI_EM_XGE_LOOPBACK
PLAT_CFLAGS += -DTI_ODP

EXTRA_CFLAGS  += $(PLAT_CFLAGS)
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
$(OBJ_DIR)/libodp.o: $(OBJS)
	$(ECHO) "  LD    $@"
	$(LD) -r -o $@ $(OBJS) $(LDFLAGS) -lopenem_rh -lopenem_osal

$(STATIC_LIB): $(OBJ_DIR)/libodp.o
	$(ECHO) "  AR    $@"
	$(AR) -cr $@ $(OBJ_DIR)/libodp.o

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
