#!/bin/bash
set -e

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	CFLAGS="-O0 -coverage $CFLAGS" CXXFLAGS="-O0 -coverage $CXXFLAGS" LDFLAGS="--coverage $LDFLAGS" \
	--enable-debug=full --enable-helper-linux --enable-dpdk
export CCACHE_DISABLE=1
make -j $(nproc)

echo 1000 | tee /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# Ignore possible failures there because these tests depends on measurements
# and systems might differ in performance.
export CI="true"

ODP_SCHEDULER=basic    make check

# Run only validation tests for scalable and sp schedulers
pushd ./test/validation/api/
ODP_SCHEDULER=scalable CI_SKIP=pktio_test_pktin_event_sched make check
ODP_SCHEDULER=sp       make check
popd

umount /mnt/huge
