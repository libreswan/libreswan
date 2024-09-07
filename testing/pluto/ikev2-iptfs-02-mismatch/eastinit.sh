/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ipv4-psk-ikev2
ipsec auto --status | grep iptfs
ipsec whack --impair suppress-retransmits
echo "initdone"
