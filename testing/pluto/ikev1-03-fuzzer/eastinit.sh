/testing/guestbin/swan-prep
ipsec _stackmanager start
# Start only one, so it is easier to spot a crash
ipsec pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add test
echo "initdone"
