#!/bin/bash
set -e

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	--host=${TARGET_ARCH} --build=x86_64-linux-gnu \
	--prefix=/opt/odp \
	--enable-dpdk \
	--without-examples \
	--without-tests \
	${CONF}

make -j $(nproc)
make install

pushd ${HOME}
git clone --depth 1 https://github.com/openeventmachine/em-odp.git
cd em-odp
./bootstrap
./configure \
	--host=${TARGET_ARCH} --build=x86_64-linux-gnu \
	--prefix=/opt/em-odp \
	--with-odp-path=/opt/odp
make -j $(nproc)
make install
popd
