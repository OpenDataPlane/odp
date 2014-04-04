# Copyright (c) 2013, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

LIBPCAP_REPO=http://git.linaro.org/git/people/vincent.hsu/libpcap.git
LIBPCAP_DIR=libpcap
TCPDUMP_REPO=https://github.com/the-tcpdump-group/tcpdump.git
TCPDUMP_DIR=tcpdump
WIRESHARK_REPO=https://code.wireshark.org/review/p/wireshark.git
WIRESHARK_DIR=wireshark
LIBPCAP_VERSION=70dd3642c58455690adb8b2e2023fb3f5e507f57
TCPDUMP_VERSION=tcpdump-4.2.1
WIRESHARK_VERSION=wireshark-1.8.9

.PHONY: all
all: libpcap tcpdump

.PHONY: update
update: get_libpcap get_tcpdump

.PHONY: install
install: install_libpcap install_tcpdump

.PHONY: clean
clean: clean_libpcap clean_tcpdump

.PHONY: libpcap
libpcap: get_libpcap
	cd $(LIBPCAP_DIR) \
	&& git checkout $(LIBPCAP_VERSION) \
	&& ./configure --with-odp=../../.. --libdir=/usr/lib
	$(MAKE) -C $(LIBPCAP_DIR)

.PHONY: get_libpcap
get_libpcap:
	if [ ! -d $(LIBPCAP_DIR) ]; then git clone $(LIBPCAP_REPO); \
	else cd $(LIBPCAP_DIR); git fetch --all; fi

.PHONY: install_libpcap
install_libpcap:
	$(MAKE) -C $(LIBPCAP_DIR) install
	if [ -d $(LIBPCAP_DIR) ]; then $(MAKE) -C $(LIBPCAP_DIR) install; fi

.PHONY: clean_libpcap
clean_libpcap:
	$(MAKE) -C $(LIBPCAP_DIR) clean
	if [ -d $(LIBPCAP_DIR) ]; then $(MAKE) -C $(LIBPCAP_DIR) distclean; fi

.PHONY: tcpdump
tcpdump: get_tcpdump libpcap
	cd $(TCPDUMP_DIR) \
	&& git checkout $(TCPDUMP_VERSION) \
	&& ./configure CC="gcc -lrt"
	$(MAKE) -C $(TCPDUMP_DIR)

.PHONY: get_tcpdump
get_tcpdump:
	if [ ! -d $(TCPDUMP_DIR) ]; then git clone $(TCPDUMP_REPO); \
	else cd $(TCPDUMP_DIR); git fetch --all; fi

.PHONY: install_tcpdump
install_tcpdump:
	$(MAKE) -C $(TCPDUMP_DIR) install
	if [ -d $(TCPDUMP_DIR) ]; then $(MAKE) -C $(TCPDUMP_DIR) install; fi

.PHONY: clean_tcpdump
clean_tcpdump:
	$(MAKE) -C $(TCPDUMP_DIR) clean
	if [ -d $(TCPDUMP_DIR) ]; then $(MAKE) -C $(TCPDUMP_DIR) distclean; fi

.PHONY: wireshark
wireshark: get_wireshark libpcap
	cd $(WIRESHARK_DIR) \
	&& git checkout $(WIRESHARK_VERSION) \
	&& ./autogen.sh && ./configure
	$(MAKE) -C $(WIRESHARK_DIR)

.PHONY: get_wireshark
get_wireshark:
	if [ ! -d $(WIRESHARK_DIR) ]; then git clone $(WIRESHARK_REPO); \
	else cd $(WIRESHARK_DIR); git fetch --all; fi

.PHONY: install_wireshark
install_wireshark:
	$(MAKE) -C $(WIRESHARK_DIR) install
	if [ -d $(WIRESHARK_DIR) ]; then $(MAKE) -C $(WIRESHARK_DIR) install; fi

.PHONY: clean_wireshark
clean_wireshark:
	$(MAKE) -C $(WIRESHARK_DIR) clean
	if [ -d $(WIRESHARK_DIR) ]; then $(MAKE) -C $(WIRESHARK_DIR) distclean; fi
