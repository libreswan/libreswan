/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east-any
ipsec auto --status | grep east-any
# east should have only one public key of its own
ipsec auto --listpubkeys
echo "initdone"
