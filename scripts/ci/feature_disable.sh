#!/bin/bash
set -e

"`dirname "$0"`"/build_x86_64.sh

cd "$(dirname "$0")"/../..

echo 1000 | tee /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# Run with the default config
./example/sysinfo/odp_sysinfo

# Run with unused features disabled
ODP_CONFIG_FILE=/odp/platform/linux-generic/test/feature_disable.conf ./example/sysinfo/odp_sysinfo

umount /mnt/huge

