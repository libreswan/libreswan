/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add east-westnet-eastnet
ipsec auto --listpubkeys
ipsec auto --status | grep east-westnet-eastnet
echo "initdone"
