/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add road-eastnet-psk
ipsec auto --status | grep road-eastnet-psk
echo "initdone"
