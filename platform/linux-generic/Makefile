## Copyright (c) 2013, Linaro Limited
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions are met:
##
##    * Redistributions of source code must retain the above copyright notice, this
##      list of conditions and the following disclaimer.
##
##    * Redistributions in binary form must reproduce the above copyright notice, this
##      list of conditions and the following disclaimer in the documentation and/or
##      other materials provided with the distribution.
##
##    * Neither the name of Linaro Limited nor the names of its contributors may be
##      used to endorse or promote products derived from this software without specific
##      prior written permission.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
## WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
## DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
## SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
## CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
## OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
## OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

.DEFAULT_GOAL := libs

ODP_ROOT = ../..
LIB_DIR  = ./lib
DOC_DIR  = ./doc

EXTRA_CFLAGS  += -I$(ODP_ROOT)/include
EXTRA_CFLAGS  += -I./include
EXTRA_CFLAGS  += -I./include/api

# Option for shared libraries.
# Decreases performance with static libraries.
# EXTRA_CFLAGS  += -fPIC

ifeq ($(ODP_HAVE_NETMAP),yes)
EXTRA_CFLAGS  += -DODP_HAVE_NETMAP
endif

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
ifeq ($(ODP_HAVE_NETMAP),yes)
OBJS    += $(OBJ_DIR)/odp_packet_netmap.o
endif

DEPS     = $(OBJS:.o=.d)

.PHONY: all
all: libs docs

-include $(DEPS)

$(LIB_DIR):
	$(MKDIR) $(LIB_DIR)

$(DOC_DIR):
	$(MKDIR) $(DOC_DIR)/html
	$(MKDIR) $(DOC_DIR)/latex

#
# Compile rules
#
$(OBJ_DIR)/%.o: ./source/%.c
	$(ECHO) Compiling $<
	$(CC) -c -MD $(EXTRA_CFLAGS) $(CFLAGS) -o $@ $<

#
# Lib rule
#
$(STATIC_LIB): $(OBJS)
	$(AR) -cr $@ $(OBJS)

clean:
	$(RMDIR) $(OBJ_DIR)
	$(RMDIR) $(LIB_DIR)
	$(RMDIR) $(DOC_DIR)
	$(RM) Doxyfile

Doxyfile: Doxyfile.in
	doxygen -u - < $< > $@

.PHONY: docs
docs: $(DOC_DIR) Doxyfile ./include/odp*.h
	doxygen

.PHONY: docs_install
docs_install: docs
	$(COPY) doc $(DESTDIR)

.PHONY: pdf
pdf: docs
	make --directory doc/latex refman.pdf 1> /dev/null

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
	$(COPY) include/api/* $(DESTDIR)/include/

install: lib_install headers_install
