/testing/guestbin/swan-prep
ping -c 2 192.1.2.23
ping -c 2 192.1.2.45
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-retransmits
ipsec auto --add road-east
ipsec auto --add road-west
ipsec auto --status
echo "initdone"
