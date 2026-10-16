/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add road-east-ikev2
ipsec connectionstatus road-east-ikev2
# east should have only one pub key not road.
ipsec listpubkeys
echo "initdone"