#!/bin/bash
set -e

export TARGET_ARCH=riscv64-linux-gnu
if [ "${CC#clang}" != "${CC}" ] ; then
	export CC="clang --target=${TARGET_ARCH}"
	export CXX="clang++ --target=${TARGET_ARCH}"
else
	export CC="${TARGET_ARCH}-gcc"
	export CXX="${TARGET_ARCH}-g++"
fi

# Use target libraries
export PKG_CONFIG_PATH=
export PKG_CONFIG_LIBDIR=/usr/lib/${TARGET_ARCH}/pkgconfig

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	--host=${TARGET_ARCH} --build=x86_64-linux-gnu \
	--prefix=/opt/odp \
	${CONF}

make clean

make -j $(nproc)

make install

make installcheck
