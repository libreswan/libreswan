/testing/guestbin/swan-prep

ip addr add 192.0.100.254/24 dev eth0:1
ip addr add 192.0.110.254/24 dev eth0:1

../../guestbin/route.sh add 192.0.200.0/24 via 192.1.2.23  dev eth1
../../guestbin/route.sh add 192.0.210.0/24 via 192.1.2.23  dev eth1

# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -A INPUT -i eth1 -s 192.0.200.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair timeout_on_retransmit

ipsec auto --add westnet-eastnet-ikev2

ipsec auto --add westnet-eastnet-ikev2-00
ipsec auto --add westnet-eastnet-ikev2-10

echo "initdone"
