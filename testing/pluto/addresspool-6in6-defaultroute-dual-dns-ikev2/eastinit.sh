/testing/guestbin/swan-prep --46 --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east
echo "initdone"
