/testing/guestbin/swan-prep
ipsec _stackmanager start
ipsec pluto --config /etc/ipsec.conf --leak-detective
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair-retransmits
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
