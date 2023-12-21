#!/bin/sh
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2015-2018 Linaro Limited
# Copyright (c) 2023 Nokia
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

STARTTIME=30
RUNTIME1=3
RUNTIME2=1
TIMEOUT=3
if [ "${TEST}" = "coverage" ]; then
	RUNTIME1=30
	RUNTIME2=15
	TIMEOUT=20
fi

run()
{
	local ret=0

	echo "==== run pktio_ipc1 then pktio_ipc2 ===="
	pktio_ipc1${EXEEXT} -s ${STARTTIME} -t ${RUNTIME1} &
	IPC_PID=$!

	pktio_ipc2${EXEEXT} -p ${IPC_PID}  -s ${STARTTIME} -t ${RUNTIME2}
	ret=$?
	# pktio_ipc1 should do clean up and exit just
	# after pktio_ipc2 exited. If it does not happen
	# kill him in test.
	sleep ${TIMEOUT}
	(kill ${IPC_PID} 2>&1 > /dev/null ) > /dev/null
	if [ $? -eq 0 ]; then
		echo "pktio_ipc1${EXEEXT} was killed"
		ls -l /dev/shm/${UID}/odp* 2> /dev/null
		rm -rf /dev/shm/${UID}/odp-${IPC_PID}* 2>&1 > /dev/null
	else
		echo "normal exit of 2 application"
		ls -l /dev/shm/${UID}/odp* 2> /dev/null
	fi

	if [ $ret -ne 0 ]; then
		echo "!!!First stage  FAILED $ret!!!"
		exit $ret
	else
		echo "First stage PASSED"
	fi

	echo "==== run pktio_ipc2 then pktio_ipc1 ===="
	pktio_ipc2${EXEEXT}  -s ${STARTTIME} -t ${RUNTIME1} &
	IPC_PID=$!

	pktio_ipc1${EXEEXT} -p ${IPC_PID}  -s ${STARTTIME} -t ${RUNTIME2}
	ret=$?
	# pktio_ipc2 do not exit on pktio_ipc1 disconnect
	# wait until it exits cleanly
	sleep ${TIMEOUT}
	(kill ${IPC_PID} 2>&1 > /dev/null ) > /dev/null
	if [ $? -eq 0 ]; then
		echo "pktio_ipc2${EXEEXT} was killed"
		ls -l /dev/shm/${UID}/odp* 2> /dev/null
		rm -rf /dev/shm/${UID}/odp-${IPC_PID}* 2>&1 > /dev/null
	else
		echo "normal exit of 2 application"
		ls -l /dev/shm/${UID}/odp* 2> /dev/null
	fi

	if [ $ret -ne 0 ]; then
		echo "!!! FAILED !!!"
		ls -l /dev/shm/${UID}/odp* 2> /dev/null
		rm -rf /dev/shm/${UID}/odp-${IPC_PID}* 2>&1 > /dev/null
		exit $ret
	else
		ls -l /dev/shm/${UID}/odp* 2> /dev/null
		echo "Second stage PASSED"
	fi

	echo "!!!PASSED!!!"
	exit 0
}

case "$1" in
	*)       run ;;
esac
