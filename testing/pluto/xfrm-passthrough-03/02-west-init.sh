/testing/guestbin/swan-prep --hostkeys
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.1.2.45 192.1.2.23
# ensure that clear text does not get through
iptables -A INPUT -i eth0 -s 192.1.2.23/32 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east
ipsec auto --add west-east-passthrough-a
ipsec auto --add west-east-passthrough-b
ipsec auto --route west-east-passthrough-a
ipsec auto --route west-east-passthrough-b
ipsec whack --impair suppress_retransmits
ipsec whack --impair suppress_retransmits
echo "initdone"
