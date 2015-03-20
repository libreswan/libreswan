/testing/guestbin/swan-prep
ipsec _stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east
ipsec auto --add west-eastnet
ipsec auto --add westnet-east
/testing/pluto/bin/wait-until-policy-loaded
echo "initdone"
