/testing/guestbin/swan-prep
ipsec _stackmanager start
ipsec pluto --config /etc/ipsec.conf --natikeport 1000 --ikeport 999
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add porttest
ipsec auto --status
echo "initdone"
