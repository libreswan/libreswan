/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east
ipsec auto --status | grep road-east
# eash should have only one pub key not road.
ipsec auto --listpubkeys
echo "initdone"
