/testing/guestbin/swan-prep --nokeys
ip address del 192.0.1.254/24 dev eth0 >/dev/null
../../guestbin/ip.sh link set dev eth0 down 2>/dev/null
../../guestbin/ip.sh link set dev ipsec17 down 2>/dev/null
../../guestbin/ip.sh link delete ipsec17 2>/dev/null
../../guestbin/ip.sh route get to 192.0.2.254 | grep eth1 && ip route del 192.0.2.0/24 via 192.1.2.23 dev eth1
# keep "dev eth1" in the next line, to test corner cases
../../guestbin/ip.sh link add ipsec17 type xfrm if_id 17 dev eth1
../../guestbin/ip.sh -d link show dev ipsec17
ip address add 192.0.1.254/24 dev ipsec17
../../guestbin/ip-addr-show.sh
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west
echo "initdone"
