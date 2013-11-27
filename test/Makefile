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


ODP_ROOT = ..
ARCH     = linux-generic
ODP_LIB  = $(ODP_ROOT)/arch/$(ARCH)
OBJ_DIR  = ./obj
LIB      = $(ODP_LIB)/lib/odp.a
ODP_APP  = odp_app

CC       = @gcc



E_FLAGS  = -W -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes 
E_FLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith 
E_FLAGS += -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral 
E_FLAGS += -Wformat-security -Wundef -Wwrite-strings

CFLAGS  += -pthread
CFLAGS  += -I.
CFLAGS  += -I$(ODP_LIB)
CFLAGS  += $(E_FLAGS)
#CFLAGS  += -DODP_TEST_ATOMIC

LDFLAGS += -pthread
LDFLAGS += -lrt

OBJS     =
OBJS    += $(OBJ_DIR)/odp_test_api.o
OBJS    += $(OBJ_DIR)/odp_test_atomic.o


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
	install -d $(DEST)$(prefix)/lib
	install -m 0644 ${LIB} $(DEST)$(prefix)/lib/
	install -d $(DEST)$(prefix)/share/odp
	install -m 0755 $(ODP_APP) $(DEST)$(prefix)/share/odp/
