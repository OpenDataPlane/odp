#!/bin/bash
set -e

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	--host=${TARGET_ARCH} --build=x86_64-linux-gnu \
	--enable-dpdk \
	${CONF}

make -j 8
