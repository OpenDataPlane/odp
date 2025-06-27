#!/bin/sh
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2015 Ilya Maximets <i.maximets@samsung.com>
#


# any parameter passed as arguments to this script is passed unchanged to
# the test itself (pktio_main)

# directories where pktio_main binary can be found:
# -in the validation dir when running make check (intree or out of tree)
# -in the script directory, when running after 'make install', or
# -in the validation when running standalone intree.
# -in the current directory.
# running stand alone out of tree requires setting PATH
PATH=${TEST_DIR}/api/pktio:$PATH
PATH=$(dirname $0):$PATH
PATH=$(dirname $0)/../../../../../../test/validation/api/pktio:$PATH
PATH=.:$PATH

pktio_main_path=$(which pktio_main${EXEEXT})
if [ -x "$pktio_main_path" ] ; then
	echo "running with $pktio_main_path"
else
	echo "cannot find pktio_main${EXEEXT}: please set you PATH for it."
fi

# exit code expected by automake for skipped tests
TEST_SKIPPED=77

TAP_BASE_NAME=iotap_vald
IF0=${TAP_BASE_NAME}0
IF1=${TAP_BASE_NAME}1
BR=${TAP_BASE_NAME}_br

export ODP_PKTIO_IF0="tap:$IF0"
export ODP_PKTIO_IF1="tap:$IF1"

tap_cleanup()
{
	ret=$?

	for iface in $IF0 $IF1; do
		ip link set dev $iface nomaster
	done

	ip link delete $BR type bridge

	for iface in $IF0 $IF1; do
		ip tuntap del mode tap $iface
	done

	trap - EXIT
	exit $ret
}

tap_setup()
{
	if [ "$(id -u)" != "0" ]; then
		echo "pktio: need to be root to setup TAP interfaces."
		return $TEST_SKIPPED
	fi

	for iface in $IF0 $IF1 $BR; do
		ip link show $iface 2> /dev/null
		if [ $? -eq 0 ]; then
			echo "pktio: interface $iface already exist $?"
			return 2
		fi
	done

	trap tap_cleanup EXIT

	for iface in $IF0 $IF1; do
		ip tuntap add mode tap $iface
		if [ $? -ne 0 ]; then
			echo "pktio: error: unable to create TAP device $iface"
			return 3
		fi
	done

	ip link add name $BR type bridge
	if [ $? -ne 0 ]; then
		echo "pktio: error: unable to create bridge $BR"
		return 3
	fi

	for iface in $IF0 $IF1; do
		ip link set dev $iface master $BR
		if [ $? -ne 0 ]; then
			echo "pktio: error: unable to add $iface to bridge $BR"
			return 4
		fi
	done

	for iface in $IF0 $IF1 $BR; do
		ifconfig $iface -arp
		sysctl -w net.ipv6.conf.${iface}.disable_ipv6=1
		ip link set dev $iface mtu 9216 up
	done

	return 0
}

tap_setup
ret=$?
if [ $ret -ne 0 ]; then
	echo "pktio: tap_setup() FAILED!"
	exit $TEST_SKIPPED
fi

pktio_main${EXEEXT} $*
ret=$?

exit $ret
