/testing/guestbin/swan-prep --nokeys
# confirm that the network is alive
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east-delete1
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
echo "initdone"
