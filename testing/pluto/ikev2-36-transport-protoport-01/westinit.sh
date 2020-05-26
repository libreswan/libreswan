/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ipv4-psk-ikev2-transport
ipsec whack --impair suppress-retransmits
echo "initdone"
