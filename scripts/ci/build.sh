#!/bin/bash
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

pushd ${HOME}
${CC} ${CFLAGS} ${OLDPWD}/example/sysinfo/odp_sysinfo.c -o odp_sysinfo_inst_dynamic `PKG_CONFIG_PATH=/opt/odp/lib/pkgconfig:${PKG_CONFIG_PATH} pkg-config --cflags --libs libodp-linux`
if [ -z "$TARGET_ARCH" ] || [ "$TARGET_ARCH" == "$BUILD_ARCH" ]
then
	LD_LIBRARY_PATH="/opt/odp/lib:$LD_LIBRARY_PATH" ./odp_sysinfo_inst_dynamic
fi
popd
