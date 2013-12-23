# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause


E_FLAGS  = -W -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes
E_FLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith
E_FLAGS += -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral
E_FLAGS += -Wformat-security -Wundef -Wwrite-strings

CFLAGS  += $(E_FLAGS)

.PHONY: all
all:
	 $(MAKE) -C api_test
	 $(MAKE) -C example
	 $(MAKE) -C packet

.PHONY: clean
clean:
	 $(MAKE) -C api_test clean
	 $(MAKE) -C example clean
	 $(MAKE) -C packet clean

.PHONY: install
install:
	 $(MAKE) -C api_test install
	 $(MAKE) -C example install
	 $(MAKE) -C packet install
