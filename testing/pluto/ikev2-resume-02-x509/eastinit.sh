../../guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east
echo "initdone"
