#!/bin/bash
set -e

echo 1000 | tee /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

"`dirname "$0"`"/build_${ARCH}.sh

cd "$(dirname "$0")"/../..

./platform/linux-generic/test/validation/api/pktio/pktio_run.sh

umount /mnt/huge
