# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause

TESTS=$(filter %, $(wildcard */))

.PHONY: all clean install

all: $(TESTS)
	for T in $(TESTS); do $(MAKE) -C $$T || exit 1; done

clean:
	for T in $(TESTS); do $(MAKE) -C $$T clean || true; done

install:
	for T in $(TESTS); do $(MAKE) -C $$T install ||exit 1; done
