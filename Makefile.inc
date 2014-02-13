# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause

PLATFORM ?= linux-generic
CFLAGS  += -DODP_DEBUG=1
#CFLAGS  += -O3
CFLAGS  += -O0 -g

OBJ_DIR  = ./obj
DESTDIR ?= $(ODP_ROOT)/build

CFLAGS += -W -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
CFLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith
CFLAGS += -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral
CFLAGS += -Wformat-security -Wundef -Wwrite-strings

CC     ?= gcc
LD     ?= gcc
AR     ?= ar

ECHO   := echo
MKDIR  := mkdir -p
RMDIR  := rm -rf
RM     := rm -f
COPY   := cp -r

CFLAGS  += -pthread
LDFLAGS += -pthread
