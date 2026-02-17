#!/usr/bin/env bash
#
# Test output AH
#  - 2 loop interfaces
#  - 10 packets
#  - Specify API mode on command line

# IPSEC_APP_MODE: 0 - STANDALONE, 1 - LIVE, 2 - ROUTER
IPSEC_APP_MODE=0

if  [ -f ./pktio_env ]; then
	. ./pktio_env
else
	echo "BUG: unable to find pktio_env!"
	echo "pktio_env has to be in current directory"
	exit 1
fi

setup_interfaces

./odp_ipsec_api -i $IF_LIST \
	-r 192.168.222.2/32,$ROUTE_IF_OUTB,08:00:27:F5:8B:DB \
	-p 192.168.111.0/24,192.168.222.0/24,out,ah \
	-a 192.168.111.2,192.168.222.2,sha1,200,a731649644c5dee92cbd9c2e7e188ee600000000 \
	-t 192.168.111.2,192.168.222.2,10.0.111.2,10.0.222.2 \
	-s 192.168.111.2,192.168.222.2,$IN_IF,$OUT_IF,10,100 \
	-c 2 "$@"

STATUS=$?

if [ ${STATUS} -ne 0 ]; then
	echo "Error: status ${STATUS}"
	exit 1
fi

validate_result

cleanup_interfaces

exit 0
