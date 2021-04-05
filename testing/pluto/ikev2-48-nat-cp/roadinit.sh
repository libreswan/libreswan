/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
