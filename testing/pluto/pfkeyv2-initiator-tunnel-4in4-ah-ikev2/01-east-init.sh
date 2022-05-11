/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add eastnet-westnet-ikev2
ipsec whack --impair suppress-retransmits
echo "initdone"
