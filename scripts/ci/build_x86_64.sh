#!/bin/bash
set -e

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	--enable-dpdk \
	${CONF}

make -j 8

echo 1000 | tee /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# Ignore possible failures there because these tests depends on measurements
# and systems might differ in performance.
export CI="true"
make check

umount /mnt/huge
