: ==== start ====
TESTNAME=loopback-pluto-03
source /testing/pluto/bin/westlocal.sh

# confirm that the network is alive
ping -n -c 4 127.0.0.1
# make sure that clear text does not get through
#iptables -A INPUT -i lo -p icmp -j DROP
# confirm with a ping 
#ping -n -c 4 127.0.0.1

ipsec setup start
ipsec auto --add loopback-03-westleft
/testing/pluto/bin/wait-until-pluto-started

echo done

