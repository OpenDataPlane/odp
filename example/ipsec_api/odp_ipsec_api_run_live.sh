#!/bin/bash
#
# Live router test
#  - 2 interfaces interfaces
#  - Specify API mode on command line
sudo ./odp_ipsec_api -i p7p1,p8p1 \
-r 192.168.111.2/32:p7p1:08.00.27.76.B5.E0 \
-r 192.168.222.2/32:p8p1:08.00.27.F5.8B.DB \
-p 192.168.111.0/24:192.168.222.0/24:out:esp \
-e 192.168.111.2:192.168.222.2:\
3des:201:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224 \
-p 192.168.222.0/24:192.168.111.0/24:in:esp \
-e 192.168.222.2:192.168.111.2:\
3des:301:c966199f24d095f3990a320d749056401e82b26570320292 \
-c 2 "$@"
