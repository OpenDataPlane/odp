#!/bin/bash
set -e

# CC LD AR CXX has to be predifubed
#

export PKG_CONFIG_PATH="$HOME/cunit-install/x86_64/lib/pkgconfig:${PKG_CONFIG_PATH}"

CWD=$(dirname "$0")
TDIR=`mktemp -d -p ~`

cd ${TDIR}
git clone ${CWD}/../../ odp
cd ./odp
./bootstrap
./configure --enable-user-guides

make clean
make distcheck

make clean
make distcheck DISTCHECK__CONFIGURE_FLAGS=--disable-abi-compat

cd ~
rm -rf ${TDIR}
