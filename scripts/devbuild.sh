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
	echo "Usage: $0 [dpdk | odp | odp-check | odp_*]" >&2
	echo "Build DPDK, ODP-DPDK or both. You need a successful build of " \
	 "the first to build the second." >&2
	echo "odp-check runs all unit tests (make check), but you can run " \
	 "them separately as well, e.g. odp_buffer." >&2
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

for i in "$@"
do
case $i in
	dpdk)
		cd $CHECK_ODP_DIR
		# Build only DPDK
		export BUILD_DEPS=2
		./build-dpdk.sh
	;;
	odp)
		cd $CHECK_ODP_DIR
		git clean -xfd
		# That prevents make check to run 
		export ARCH=nocheck
		# Don't build DPDK
		export BUILD_DEPS=0
		./build-dpdk.sh
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
		sudo ODP_PLATFORM_PARAMS="-n 3" make check
		sleep 1 && sudo umount -a -t hugetlbfs
	;;
	odp_*)
		cd $ODP_BUILDDIR
		if [ ! -d $HUGEPAGEDIR ]; then
			sudo mkdir $HUGEPAGEDIR
		fi
		sudo mount -t hugetlbfs nodev $HUGEPAGEDIR
		sudo sh -c 'echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages'
		echo "Total number: `cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages`"
		echo "Free pages: `cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages`"
		sudo ODP_PLATFORM_PARAMS="-n 3" test/validation/$i
		sleep 1 && sudo umount -a -t hugetlbfs
	;;
esac
done
