/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add rekey
ipsec auto --add rekey1
ipsec auto --add rekey2
echo "initdone"
