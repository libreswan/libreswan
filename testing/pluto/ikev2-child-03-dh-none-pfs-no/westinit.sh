/testing/guestbin/swan-prep

ip addr add 192.0.100.254/24 dev eth0:1
ip addr add 192.0.101.254/24 dev eth0:1
ip addr add 192.0.110.254/24 dev eth0:1
ip addr add 192.0.111.254/24 dev eth0:1

ip route add 192.0.200.0/24 via 192.1.2.23  dev eth1
ip route add 192.0.201.0/24 via 192.1.2.23  dev eth1
ip route add 192.0.210.0/24 via 192.1.2.23  dev eth1
ip route add 192.0.211.0/24 via 192.1.2.23  dev eth1

# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
iptables -A INPUT -i eth1 -s 192.0.200.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits,delete-on-retransmit

ipsec auto --add westnet-eastnet-ikev2

ipsec auto --add westnet-eastnet-ikev2-00
ipsec auto --add westnet-eastnet-ikev2-01
ipsec auto --add westnet-eastnet-ikev2-10
ipsec auto --add westnet-eastnet-ikev2-11

echo "initdone"
