#!/bin/bash

export ODP_PLATFORM_PARAMS=${ODP_PLATFORM_PARAMS:--n 4}
# where to mount huge pages
export HUGEPAGEDIR=${HUGEPAGEDIR:-/mnt/huge}

# Make sure huge pages are released when a unit test crashes "make check"
trap ctrl_c INT

ctrl_c() {
	echo "** Trapped CTRL-C"
	if grep -qs "$HUGEPAGEDIR" /proc/mounts; then
		echo "** Umounting hugetlbfs"
		sleep 1 && sudo umount -a -t hugetlbfs
	fi
}

if [ ! -d $HUGEPAGEDIR ]; then
	sudo mkdir -p $HUGEPAGEDIR
fi
if grep -qs "$HUGEPAGEDIR" /proc/mounts; then
	echo "Umounting hugetlbfs from previous run!"
	sudo umount -a -t hugetlbfs
fi
echo "Mounting hugetlbfs"
sudo mount -t hugetlbfs -o pagesize=1G nodev $HUGEPAGEDIR 2>/dev/null
res=$?
if [ $res -ne 0 ]; then
	echo "Using 2MB pages"
	sudo mount -t hugetlbfs nodev $HUGEPAGEDIR
	res=$?
	if [ $res -ne 0 ]; then
		echo "ERROR: can't mount hugepages"
		exit $res
	fi
	sudo sh -c 'echo 256 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages'
	if [ `cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages` -lt 1 ]; then
		echo "Failed to reserve at least 1 huge page!"
		exit 1
	else
		echo "Total number: `cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages`"
		echo "Free pages: `cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages`"
	fi
else
	echo "Using 1GB pages"
	sudo sh -c 'echo 1 > /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages'
	if [ `cat /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages` -lt 1 ]; then
		echo "Failed to reserve at least 1 huge page!"
		exit 1
	else
		echo "Total number: `cat /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages`"
		echo "Free pages: `cat /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/free_hugepages`"
	fi
fi
echo "running $1!"
sudo ODP_PLATFORM_PARAMS="$ODP_PLATFORM_PARAMS" $1
res=$?
echo "Unmounting hugetlbfs"
sleep 0.3 && sudo umount -a -t hugetlbfs
exit $res

