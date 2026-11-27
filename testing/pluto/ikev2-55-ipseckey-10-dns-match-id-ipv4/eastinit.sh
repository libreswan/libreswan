/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east-ikev2
ipsec auto --status | grep road-east-ikev2
# eash should have only one pub key not road.
ipsec auto --listpubkeys
echo "initdone"
