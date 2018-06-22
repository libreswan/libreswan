/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add east-any
ipsec auto --status | grep east-any
# east should have only one public key of its own
ipsec auto --listpubkeys
echo "initdone"
