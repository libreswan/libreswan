/testing/guestbin/swan-prep
# ensure that clear text does not get through
# this route from /etc/sysconfig/network-scripts/route-eth1 interferes
../../guestbin/route.sh get to 192.0.2.254 | grep eth1 && ip route del 192.0.2.0/24 via 192.1.2.23 dev eth1
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west
echo "initdone"
