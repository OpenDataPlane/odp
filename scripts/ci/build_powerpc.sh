#!/bin/bash
set -e

if [ "${CC#clang}" != "${CC}" ] ; then
	export CC="clang --target=powerpc-linux-gnu"
	export LD="clang --target=powerpc-linux-gnu"
	export CXX="clang++ --target=powerpc-linux-gnu"
	export AR=powerpc-linux-gnu-ar
else
	export CC=powerpc-linux-gnu-gcc
	export LD=powerpc-linux-gnu-ld
	export AR=powerpc-linux-gnu-ar
fi

export PKG_CONFIG_PATH=/usr/lib/powerpc-linux-gnu/pkgconfig:/usr/powerpc-linux-gnu/pkgconfig
export PKG_CONFIG_PATH="$HOME/cunit-install/powerpc-linux-gnu/lib/pkgconfig:${PKG_CONFIG_PATH}"

CWD=$(dirname "$0")
TDIR=`mktemp -d -p ~`

cd ${TDIR}

git clone ${CWD}/../../ odp
cd ./odp
./bootstrap
./configure --host=powerpc-linux-gnu --build=x86_64-linux-gnu \
	--disable-test-cpp ${CONF}

make clean
make -j 8
cd ~ 
rm -rf ${TDIR}
