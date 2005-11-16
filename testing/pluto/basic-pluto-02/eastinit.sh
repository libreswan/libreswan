# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP

ipsec setup start
: intentionally comment out this policy
# ipsec auto --add westnet-eastnet
/testing/pluto/basic-pluto-01/eroutewait.sh trap
