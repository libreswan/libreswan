/testing/guestbin/swan-prep --nokeys
# confirm that the network is alive
../../guestbin/wait-until-alive 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down 192.0.2.254
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2-gcm-c
ipsec auto --status
ipsec whack --impair suppress_retransmits
echo "initdone"
