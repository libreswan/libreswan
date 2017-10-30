/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east-ikev2
ipsec auto --status | grep road-east-ikev2
# east should have only one public key of its own
ipsec auto --listpubkeys
echo "initdone"
