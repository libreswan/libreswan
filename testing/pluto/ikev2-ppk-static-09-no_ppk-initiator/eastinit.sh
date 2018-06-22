/testing/guestbin/swan-prep
ipsec _stackmanager start
ipsec pluto --config /etc/ipsec.conf --leak-detective
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ppk
ipsec auto --status | grep westnet-eastnet-ipv4-psk-ppk
echo "initdone"
