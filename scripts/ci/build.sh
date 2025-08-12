#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	--host=${TARGET_ARCH} --build=${BUILD_ARCH:-x86_64-linux-gnu} \
	--enable-dpdk \
	--prefix=/opt/odp \
	${CONF}

make clean

make -j $(nproc)

make install

make installcheck
