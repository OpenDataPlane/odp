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
sudo mount -t hugetlbfs nodev $HUGEPAGEDIR
sudo sh -c 'echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages'
echo "Total number: `cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages`"
echo "Free pages: `cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages`"
echo "running $1!"
sudo ODP_PLATFORM_PARAMS="$ODP_PLATFORM_PARAMS" $1
res=$?
if [ $res -ne 0 ]; then
	tail -n 80 $1.log > /dev/tty
fi
echo "Unmounting hugetlbfs"
sleep 0.3 && sudo umount -a -t hugetlbfs
exit $res

