/testing/guestbin/swan-prep
# confirm that the network is alive
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-retransmits
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
ipsec auto --status
echo "initdone"
