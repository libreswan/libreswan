/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair retransmits
ipsec auto --add road-east-1
echo "initdone"
