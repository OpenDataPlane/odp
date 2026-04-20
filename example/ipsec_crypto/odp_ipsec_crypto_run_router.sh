#!/usr/bin/env bash
#
# Live router test
#  - 2 interfaces interfaces
#  - Specify API mode on command line

# IPSEC_APP_MODE: 0 - STANDALONE, 1 - LIVE, 2 - ROUTER
IPSEC_APP_MODE=2

if  [ -f ./pktio_env ]; then
	. ./pktio_env
else
	echo "BUG: unable to find pktio_env!"
	echo "pktio_env has to be in current directory"
	exit 1
fi

setup_interfaces

# this just turns off output buffering so that you still get periodic
# output while piping to tee, as long as stdbuf is available.
STDBUF="`which stdbuf 2>/dev/null` -o 0" || STDBUF=
LOG=odp_ipsec_crypto_tmp.log
PID=app_pid

($STDBUF \
 ./odp_ipsec_crypto -i $IF0,$IF1 \
	-r 192.168.111.2/32,$IF0,$NEXT_HOP_MAC0 \
	-r 192.168.222.2/32,$IF1,$NEXT_HOP_MAC1 \
	-c 1 "$@" & echo $! > $PID) | tee -a $LOG &

# Wait till application thread starts.
APP_READY="Pktio thread \[..\] starts"

until [ -f $LOG ]
do
	sleep 1
done

tail -f $LOG | grep -qm 1 "$APP_READY"

validate_result
ret=$?

APP_PID=`cat $PID`

kill -2 ${APP_PID}

# Wait till the application exits
tail --pid=$APP_PID -f /dev/null

rm -f $PID
rm -f $LOG

cleanup_interfaces

exit $ret
