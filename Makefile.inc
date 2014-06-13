# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause

PLATFORM ?= linux-generic
OBJ_DIR   = ./obj
ODP_DIR   = $(ODP_ROOT)/platform/$(PLATFORM)

export DESTDIR  = $(ODP_ROOT)/build

CC     ?= gcc
LD     ?= gcc
AR     ?= ar
ECHO   := @echo
MKDIR  := mkdir -p
RMDIR  := rm -rf
RM     := rm -f
COPY   := cp -r
SYNC   := rsync -a --delete

ifneq ($(VERBOSE),yes)
Q          = @
MAKEFLAGS += --no-print-directory
endif

QUIET_CC   = $(Q:@=@echo    '     CC       '$@;)
QUIET_LD   = $(Q:@=@echo    '     LD       '$@;)
QUIET_AR   = $(Q:@=@echo    '     AR       '$@;)
export Q QUIET_CC QUIET_LD QUIET_AR

ifeq ($(ODP_DEBUG_PRINT),no)
EXTRA_CFLAGS += -DODP_DEBUG_PRINT=0
else
EXTRA_CFLAGS += -DODP_DEBUG_PRINT=1
endif

ifeq ($(DEBUG),yes)
EXTRA_CFLAGS += -O0 -g
else
EXTRA_CFLAGS += -O3
endif

EXTRA_CFLAGS += -pthread
EXTRA_CFLAGS += -W -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
EXTRA_CFLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith
EXTRA_CFLAGS += -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral
EXTRA_CFLAGS += -Wformat-security -Wundef -Wwrite-strings


LDFLAGS += -pthread
LDFLAGS += $(CFLAGS)

STD_LIBS += -lrt

include $(wildcard $(ODP_DIR)/Makefile.inc)

.PHONY: default
default:

$(OBJ_DIR):
	$(Q)$(MKDIR) $(OBJ_DIR)
