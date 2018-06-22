/testing/guestbin/swan-prep

ip addr add 192.0.200.254/24 dev eth0:1
ip addr add 192.0.210.254/24 dev eth0:1

ip route add 192.0.100.0/24 via 192.1.2.45  dev eth1
ip route add 192.0.110.0/24 via 192.1.2.45  dev eth1

ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --add westnet-eastnet-ikev2-00
ipsec auto --add westnet-eastnet-ikev2-10

echo "initdone"
