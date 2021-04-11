/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2-b
ipsec whack --impair suppress-retransmits
echo "initdone"
