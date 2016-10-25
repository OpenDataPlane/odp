#!/bin/sh
#
# Copyright (c) 2015, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause
#

# directories where test binary can be found:
# -in the validation dir when running make check (intree or out of tree)
# -in the script directory, when running after 'make install', or
# -in the validation when running standalone (./pktio_ipc_run) intree.
# -in the current directory.
# running stand alone out of tree requires setting PATH
PATH=./pktio_ipc:$PATH
PATH=$(dirname $0):$PATH
PATH=$(dirname $0)/../../../../platform/linux-generic/test/pktio_ipc:$PATH
PATH=.:$PATH

run()
{
	local ret=0
	IPC_NS=`expr $$ + 5000`
	IPC_NS=`expr ${IPC_NS} % 65000`
	IPC_NS=`expr ${IPC_NS} + 2`
	echo "Using ns ${IPC_NS}"

	#if test was interrupted with CTRL+c than files
	#might remain in shm. Needed cleanely delete them.
	rm -rf /dev/shm/odp-${IPC_NS}* 2>&1 > /dev/null

	echo "==== run pktio_ipc1 then pktio_ipc2 ===="
	pktio_ipc1${EXEEXT} -n ${IPC_NS} -t 30 &
	IPC_PID=$!

	pktio_ipc2${EXEEXT} -n ${IPC_NS} -t 10
	ret=$?
	# pktio_ipc1 should do clean up and exit just
	# after pktio_ipc2 exited. If it does not happen
	# kill him in test.
	sleep 1
	kill ${IPC_PID} 2>&1 > /dev/null
	if [ $? -eq 0 ]; then
		rm -rf /dev/shm/odp-${IPC_NS}* 2>&1 > /dev/null
	fi

	if [ $ret -ne 0 ]; then
		echo "!!!First stage  FAILED $ret!!!"
		ls -l /dev/shm/
		exit $ret
	else
		echo "First stage PASSED"
	fi


	echo "==== run pktio_ipc2 then pktio_ipc1 ===="
	IPC_NS=`expr $IPC_NS - 1`
	echo "Using ns ${IPC_NS}"

	pktio_ipc2${EXEEXT} -n ${IPC_NS} -t 10 &
	IPC_PID=$!

	pktio_ipc1${EXEEXT} -n ${IPC_NS} -t 20
	ret=$?
	(kill ${IPC_PID} 2>&1 > /dev/null) > /dev/null || true

	if [ $ret -ne 0 ]; then
		echo "!!! FAILED !!!"
		ls -l /dev/shm/
		exit $ret
	else
		echo "Second stage PASSED"
	fi

	echo "!!!PASSED!!!"
	exit 0
}

case "$1" in
	*)       run ;;
esac
