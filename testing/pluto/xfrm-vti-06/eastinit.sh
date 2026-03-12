/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add road-east-vti
echo "initdone"
