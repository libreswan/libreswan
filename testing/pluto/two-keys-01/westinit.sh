: ==== start ====
TESTNAME=two-keys-01
source /testing/pluto/bin/westlocal.sh

# confirm that the network is alive
../../pluto/bin/wait-until-alive 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
# confirm with a ping
ping -n -c 4 192.0.2.254

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet
ipsec whack --debug-control --debug-controlmore --debug-parsing --debug-crypt
ipsec auto --listpubkeys

echo done

