#!/bin/bash
set -e

TARGET_ARCH=i686-linux-gnu
if [ "${CC#clang}" != "${CC}" ] ; then
	export CC="clang --target=${TARGET_ARCH}"
	export CXX="clang++ --target=${TARGET_ARCH}"
else
	export CFLAGS="-m32"
	export CXXFLAGS="-m32"
	export LDFLAGS="-m32"
fi
export CPPFLAGS="-I/usr/include/i386-linux-gnu/dpdk"

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	--host=${TARGET_ARCH} --build=x86_64-linux-gnu \
	--enable-dpdk \
	${CONF}

make -j 8
