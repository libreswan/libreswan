/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2a
ipsec auto --add westnet-eastnet-ikev2b
echo "initdone"
