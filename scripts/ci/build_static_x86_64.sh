#!/bin/bash
set -e

CONFIG_OPT="--prefix=/opt/odp ${CONF}"

cd "$(dirname "$0")"/../..
./bootstrap
echo "./configure $CONFIG_OPT"
./configure $CONFIG_OPT

make clean

make -j $(nproc)

make install

# Build and run sysinfo with installed libs
pushd ${HOME}

${CC} ${CFLAGS} ${OLDPWD}/example/sysinfo/odp_sysinfo.c -static -o odp_sysinfo_inst_static `PKG_CONFIG_PATH=/opt/odp/lib/pkgconfig:${PKG_CONFIG_PATH} pkg-config --cflags --libs --static libodp-linux`

./odp_sysinfo_inst_static

popd
