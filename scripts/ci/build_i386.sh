#!/bin/bash
set -e

export CC=gcc
export LD=ld
export AR=ar

export PKG_CONFIG_PATH="$HOME/cunit-install/i386-linux-gnu/lib/pkgconfig:${PKG_CONFIG_PATH}"
export PKG_CONFIG_PATH="/usr/lib/i386-linux-gnu/pkgconfig:${PKG_CONFIG_PATH}"

cd ~
export CROSS_ARCH=""
#export DPDK_CROSS=arm-linux-gnueabihf-


if [ "${CC#clang}" != "${CC}" ] ; then
	export CC="clang --target=i686-linux-gnu"
	export LD="clang --target=i686-linux-gnu"
	export CXX="clang++ --target=i686-linux-gnu"
else
	export CFLAGS="-m32"
	export CXXFLAGS="-m32"
	export LDFLAGS="-m32"
fi

git clone /odp
cd ./odp
./bootstrap
./configure --host=i386-linux-gnu --build=x86_64-linux-gnu
make clean
make -j 8
cd ..
rm -rf odp
