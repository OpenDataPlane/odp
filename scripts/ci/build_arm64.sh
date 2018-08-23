#!/bin/bash
set -e

TARGET_ARCH=aarch64-linux-gnu
if [ "${CC#clang}" != "${CC}" ] ; then
	export CC="clang --target=${TARGET_ARCH}"
	export CXX="clang++ --target=${TARGET_ARCH}"
else
	export CC="${TARGET_ARCH}-gcc"
	export CXX="${TARGET_ARCH}-g++"
fi
export CPPFLAGS="-I/usr/include/${TARGET_ARCH}/dpdk"

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	--host=${TARGET_ARCH} --build=x86_64-linux-gnu \
	--enable-dpdk \
	${CONF}

make -j 8
