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
ARCH     = linux-generic
OBJ_DIR  = ./obj
LIB_DIR  = ./lib
DOC_DIR  = ./doc
INC_DIR  = $(ODP_ROOT)/include
LIB      = $(LIB_DIR)/odp.a

CC       ?= @gcc
LD       = gcc
AR       = ar


E_FLAGS  = -W -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
E_FLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith
E_FLAGS += -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral
E_FLAGS += -Wformat-security -Wundef -Wwrite-strings

CFLAGS   =
#CFLAGS += -O0 -g
CFLAGS  += -O3
CFLAGS  += -pthread
CFLAGS  += -I.
CFLAGS  += -I./source
CFLAGS  += -I$(INC_DIR)
CFLAGS  += $(E_FLAGS)
CFLAGS  += $(EXTRA_CFLAGS)
CFLAGS  += -DODP_DEBUG=$(ODP_DEBUG)

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
OBJS    += $(OBJ_DIR)/odp_ring.o


DEPS     = $(OBJS:.o=.d)


.PHONY: all
all: libs docs



-include $(DEPS)


$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(LIB_DIR):
	mkdir $(LIB_DIR)

$(DOC_DIR):
	mkdir -p $(DOC_DIR)/html
	mkdir -p $(DOC_DIR)/latex


#
# Compile rules
#
$(OBJ_DIR)/%.o: ./source/%.c
	@echo Compiling $<
	$(CC) -c -MD $(CFLAGS) -o $@ $<


#
# Lib rule
#
$(LIB): $(OBJS)
	$(AR) -cr $@ $(OBJS)


clean:
	rm -rf $(OBJ_DIR)
	rm -rf $(LIB_DIR)
	rm -rf $(DOC_DIR)
	rm -f Doxyfile

Doxyfile: Doxyfile.in
	doxygen -u - < $< > $@

.PHONY: docs
docs: $(DOC_DIR) Doxyfile $(INC_DIR)/odp*.h
	doxygen

.PHONY: pdf
pdf: docs
	make --directory doc/latex refman.pdf 1> /dev/null


.PHONY: libs
libs: $(OBJ_DIR) $(LIB_DIR) $(LIB)

