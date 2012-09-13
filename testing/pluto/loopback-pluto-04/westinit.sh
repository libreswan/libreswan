: ==== start ====
TESTNAME=loopback-pluto-04
source /testing/pluto/bin/westlocal.sh

# confirm that the network is alive
ping -n -c 4 127.0.0.1
# make sure that clear text does not get through
iptables -A INPUT -i lo -p icmp -j DROP
# confirm with a ping 
ping -n -c 4 127.0.0.1

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add loopback-04

echo done

