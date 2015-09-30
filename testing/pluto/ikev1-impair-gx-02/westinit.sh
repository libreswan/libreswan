/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-retransmits
ipsec auto --add westnet-eastnet-ipv4-psk
echo "initdone"
