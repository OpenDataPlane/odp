#!/bin/sh

# You can overwrite most of these variables with a wrapper script
# The next 4 variables specify the directories used
export REPOS=${REPOS:-/local/repo/odp}
export CHECK_ODP_DIR=${CHECK_ODP_DIR:-$REPOS/check-odp}
export ROOT_DIR_DPDK=${ROOT_DIR_DPDK:-$REPOS/dpdk}
export GENERIC_BUILDDIR=${GENERIC_BUILDDIR:-$REPOS/odp-dpdk}
# These are passed to ODP configure
export CONFIGURE_FLAGS="${CONFIGURE_FLAGS:- --enable-debug --enable-debug-print --enable-cunit-support --enable-test-vald --enable-shared=no --enable-user-guides}"
# where to mount huge pages
export HUGEPAGEDIR=${HUGEPAGEDIR:-/mnt/huge}
# don't build CUnit for us
export VALIDATION=0
# Number of threads for compiling (make -j NUM_CPUS)
export NUM_CPUS=${NUM_CPUS:-3}
# Don't delete our working directories
export CLEANUP=0
# Don't run the relocated build test
export RELOCATE_TEST=0

if [ -z $1 ]; then
	echo "Usage: $0 [dpdk | odp | odp-check | {unit_test} ]" >&2
	echo "Build DPDK, ODP-DPDK or both. You need a successful build of" \
	 "the first to build the second." >&2
	echo "odp-check runs all unit tests (make check), but you can run" \
	 "them separately as well, e.g. buffer_main." >&2
	echo "The argument after the individual unit test is passed as" \
	 "parameter, e.g \"odp_pktio_run setup\"" >&2
	exit 1
fi

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
		cd $GENERIC_BUILDDIR
		ODP_PLATFORM_PARAMS="-n 3" make check && make doxygen-html && make -C doc
	;;
	*)
		export TEST=$1
		shift
		sudo ODP_PLATFORM_PARAMS="-n 3" $GENERIC_BUILDDIR/platform/linux-dpdk/test/wrapper-script.sh $CHECK_ODP_DIR/new-build/bin/$TEST $1
		if [ "$1" = "" ]; then
			exit
		fi
	;;
esac
shift
done
