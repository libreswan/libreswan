: ==== start ====
# confirm that the network is alive
ping -n -c 4 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
# confirm with a ping
ping -n -c 4 192.0.2.254

TESTNAME=basic-pluto-07 
source /testing/pluto/bin/westlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/basic-pluto-01/eroutewait.sh trap

ipsec auto --add westnet-eastnet-twofish
ipsec auto --up  westnet-eastnet-twofish

echo done

