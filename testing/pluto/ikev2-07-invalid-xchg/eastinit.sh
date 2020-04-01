/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair bad-ikev2-auth-xchg
ipsec whack --impair suppress-retransmits
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
