#!/bin/sh

# You can overwrite most of these variables with a wrapper script
# The next 4 variables specify the directories used
export REPOS=${REPOS:-/local/repo/odp}
export CHECK_ODP_DIR=${CHECK_ODP_DIR:-$REPOS/check-odp}
export ROOT_DIR_DPDK=${ROOT_DIR_DPDK:-$REPOS/dpdk}
export ODP_BUILDDIR=${ODP_BUILDDIR:-$REPOS/odp-dpdk}
# These are passed to ODP configure
export EXTRA_FLAGS="${EXTRA_FLAGS:- --enable-debug --enable-debug-print --enable-cunit-support --enable-test-vald --enable-shared=no}"
# where to mount huge pages
export HUGEPAGEDIR=${HUGEPAGEDIR:-/mnt/huge}
# don't do performance tests, they are not working at the moment
export PERF_TEST=0
# don't build CUnit for us
export VALIDATION=0
# Number of threads for compiling (make -j NUM_CPUS)
export NUM_CPUS=${NUM_CPUS:-3}
# Don't delete our working directories
export CLEANUP=0
# Don't run the relocated build test
export RELOCATE_TEST=0

if [ -z $1 ]; then
	echo "Usage: $0 [dpdk | odp | odp-check | odp_* {param} ]" >&2
	echo "Build DPDK, ODP-DPDK or both. You need a successful build of" \
	 "the first to build the second." >&2
	echo "odp-check runs all unit tests (make check), but you can run" \
	 "them separately as well, e.g. odp_buffer." >&2
	echo "The argument after the individual unit test is passed as" \
	 "parameter, e.g \"odp_pktio_run setup\"" >&2
	exit 1
fi

# Make sure huge pages are released when a unit test crashes "make check"
trap ctrl_c INT

ctrl_c() {
	echo "** Trapped CTRL-C"
	if grep -qs "$HUGEPAGEDIR" /proc/mounts; then
		echo "** Umounting hugetlbfs"
		sleep 1 && sudo umount -a -t hugetlbfs
	fi
}

while [ "$1" != "" ];
do
case $1 in
	dpdk)
		cd $CHECK_ODP_DIR
		# Build only DPDK
		export BUILD_DEPS=2
		./build-dpdk.sh
		if [ $? -ne 0 ]; then
			exit 1
		fi
	;;
	odp)
		cd $CHECK_ODP_DIR
		git clean -xfd
		# That prevents make check to run 
		export ARCH=nocheck
		# Don't build DPDK
		export BUILD_DEPS=0
		./build-dpdk.sh
		if [ $? -ne 0 ]; then
			exit 1
		fi
	;;
	odp-check)
		cd $ODP_BUILDDIR
		if [ ! -d $HUGEPAGEDIR ]; then
			sudo mkdir $HUGEPAGEDIR
		fi
		sudo mount -t hugetlbfs nodev $HUGEPAGEDIR
		sudo sh -c 'echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages'
		echo "Total number: `cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages`"
		echo "Free pages: `cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages`"
		FOUND=`grep "pktio-p" /proc/net/dev`
		if  [ -z "$FOUND" ] ; then
			sudo ODP_PLATFORM_PARAMS="-n 3" make check
		else
			sudo ODP_PLATFORM_PARAMS="-n 3 --vdev eth_pcap0,iface=pktio-p1-p0 --vdev eth_pcap1,iface=pktio-p3-p2" ODP_PKTIO_IF0=0 ODP_PKTIO_IF1=1 make check
		fi
		sleep 1 && sudo umount -a -t hugetlbfs
	;;
	odp_*)
		export TEST=$1
		shift
		cd $CHECK_ODP_DIR/new-build/bin
		if [ ! -d $HUGEPAGEDIR ]; then
			sudo mkdir $HUGEPAGEDIR
		fi
		sudo mount -t hugetlbfs nodev $HUGEPAGEDIR
		sudo sh -c 'echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages'
		echo "Total number: `cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages`"
		echo "Free pages: `cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages`"
		FOUND=`grep "pktio-p" /proc/net/dev`
		if  [ -z "$FOUND" ] ; then

			sudo ODP_PLATFORM_PARAMS="-n 3" ./$TEST $1
		else
			sudo ODP_PLATFORM_PARAMS="-n 3 --vdev eth_pcap0,iface=pktio-p1-p0 --vdev eth_pcap1,iface=pktio-p3-p2" ODP_PKTIO_IF0=0 ODP_PKTIO_IF1=1 ./$TEST $1
		fi
		sleep 1 && sudo umount -a -t hugetlbfs
		if [ "$1" = "" ]; then
			exit
		fi
	;;
esac
shift
done
