/testing/guestbin/swan-prep --nokeys
# confirm that newtwork is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec pluto --config /etc/ipsec.conf --leak-detective
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ppk
ipsec auto --status | grep westnet-eastnet-ipv4-psk-ppk
ipsec whack --impair suppress_retransmits
echo "initdone"
