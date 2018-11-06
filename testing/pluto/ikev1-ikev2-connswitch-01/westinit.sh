/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet1
ipsec auto --add westnet-eastnet2
ipsec whack --impair suppress-retransmits
echo "initdone"
