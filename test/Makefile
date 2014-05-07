# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause

.PHONY: all
all:
	 $(MAKE) -C api_test
	 $(MAKE) -C example
	 $(MAKE) -C packet
	 $(MAKE) -C packet_netmap
	 $(MAKE) -C timer
	 $(MAKE) -C generator

.PHONY: clean
clean:
	 $(MAKE) -C api_test clean
	 $(MAKE) -C example clean
	 $(MAKE) -C packet clean
	 $(MAKE) -C packet_netmap clean
	 $(MAKE) -C timer clean
	 $(MAKE) -C generator clean

.PHONY: install
install:
	 $(MAKE) -C api_test install
	 $(MAKE) -C example install
	 $(MAKE) -C packet install
	 $(MAKE) -C packet_netmap install
	 $(MAKE) -C timer install
	 $(MAKE) -C generator install
