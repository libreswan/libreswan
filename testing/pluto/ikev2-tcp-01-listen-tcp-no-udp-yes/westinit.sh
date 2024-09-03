/testing/guestbin/swan-prep --nokeys

# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
iptables -I INPUT -i eth1 -p tcp -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec add tcp
ipsec add udp
echo "initdone"
