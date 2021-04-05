/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add westnet-eastnet
ipsec auto --add westnet-eastnet-22
ipsec auto --route westnet-eastnet-22
echo "initdone"
