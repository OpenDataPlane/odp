# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause

PLATFORM ?= linux-generic
EXTRA_CFLAGS  += -DODP_DEBUG=1
EXTRA_CFLAGS  += -O3

OBJ_DIR  = ./obj
ODP_DIR   = $(ODP_ROOT)/platform/$(PLATFORM)

EXTRA_CFLAGS += -W -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
EXTRA_CFLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith
EXTRA_CFLAGS += -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral
EXTRA_CFLAGS += -Wformat-security -Wundef -Wwrite-strings

CC     ?= gcc
LD     ?= gcc
AR     ?= ar

ECHO   := @echo
MKDIR  := mkdir -p
RMDIR  := rm -rf
RM     := rm -f
COPY   := cp -r

EXTRA_CFLAGS  += -pthread
LDFLAGS += -pthread
LDFLAGS += -lrt
LDFLAGS += $(EXTRA_CFLAGS)

.PHONY: default
default:

$(OBJ_DIR):
	$(MKDIR) $(OBJ_DIR)
