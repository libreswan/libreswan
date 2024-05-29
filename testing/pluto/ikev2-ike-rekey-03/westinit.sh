/testing/guestbin/swan-prep
ip addr show dev eth0 | grep 192.0.100.254 || ip addr add 192.0.100.254/24 dev eth0
ip addr show dev eth0 | grep 192.0.101.254 || ip addr add 192.0.101.254/24 dev eth0
../../guestbin/route.sh show scope global | grep 192.0.200.0 || ip route add 192.0.200.0/24 via 192.1.2.23  dev eth1
../../guestbin/route.sh show scope global | grep 192.0.201.0 || ip route add 192.0.201.0/24 via 192.1.2.23  dev eth1
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -A INPUT -i eth1 -s 192.0.200.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --debug-all --impair suppress_retransmits
ipsec auto --add westnet-eastnet-ikev2a
ipsec auto --add westnet-eastnet-ikev2b
ipsec auto --add westnet-eastnet-ikev2c
echo "initdone"
