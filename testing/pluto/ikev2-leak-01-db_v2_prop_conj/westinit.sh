/testing/guestbin/swan-prep --nokeys
ipsec pluto --config /etc/ipsec.conf --leak-detective
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
ipsec whack --impair revival
