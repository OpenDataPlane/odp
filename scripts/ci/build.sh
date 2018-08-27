#!/bin/bash
set -e

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	--host=${TARGET_ARCH} --build=x86_64-linux-gnu \
	--enable-dpdk \
	--prefix=/opt/odp \
	${CONF}

make -j 8

make install

pushd ${HOME}
${CC} ${CFLAGS} ${OLDPWD}/example/hello/odp_hello.c -o odp_hello_inst_dynamic `PKG_CONFIG_PATH=/opt/odp/lib/pkgconfig:${PKG_CONFIG_PATH} pkg-config --cflags --libs libodp-linux`
if [ -z "$TARGET_ARCH" ]
then
	LD_LIBRARY_PATH="/opt/odp/lib:$LD_LIBRARY_PATH" ./odp_hello_inst_dynamic
fi
popd
