ip addr del 192.1.3.33/24 dev eth1
ip addr add 10.1.1.93/24 dev eth1
ip addr add 192.1.3.4/32 dev eth1
ip route add 0.0.0.0/0 src 192.1.3.4 via 10.1.1.254 dev eth1

: check out the network configuration
ping -n -c 4 east

TESTNAME=kingnet-isp-01
source /testing/pluto/bin/northlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

