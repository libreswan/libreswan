/testing/guestbin/swan-prep --userland strongswan
../../guestbin/ip.sh address add 192.0.4.254/32 dev eth0
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.4.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
../../guestbin/ping-once.sh --down -I 192.0.4.254 192.0.2.254
../../guestbin/strongswan-start.sh
echo "initdone"
