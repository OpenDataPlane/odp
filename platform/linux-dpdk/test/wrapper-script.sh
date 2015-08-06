#!/bin/bash

export ODP_PLATFORM_PARAMS=${ODP_PLATFORM_PARAMS:--n 4}
# where to mount huge pages
export HUGEPAGEDIR=${HUGEPAGEDIR:-/mnt/huge}

if [ ! -d $HUGEPAGEDIR ]; then
	sudo mkdir $HUGEPAGEDIR
fi
echo "Mounting hugetlbfs"
sudo mount -t hugetlbfs nodev $HUGEPAGEDIR
sudo sh -c 'echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages'
echo "Total number: `cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages`"
echo "Free pages: `cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages`"
echo "running $1!"
sudo ODP_PLATFORM_PARAMS="$ODP_PLATFORM_PARAMS" $1
res=$?
echo "Unmounting hugetlbfs"
sleep 0.3 && sudo umount -a -t hugetlbfs
exit $res

