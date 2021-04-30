#!/bin/bash
set -e

"`dirname "$0"`"/build_${ARCH}.sh

cd "$(dirname "$0")"/../..

echo 1000 | tee /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

ODP_SCHEDULER=basic    ./test/validation/api/timer/timer_main
ODP_SCHEDULER=sp       ./test/validation/api/timer/timer_main
ODP_SCHEDULER=scalable ./test/validation/api/timer/timer_main

umount /mnt/huge
