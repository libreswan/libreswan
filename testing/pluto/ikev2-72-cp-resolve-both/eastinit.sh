/testing/guestbin/swan-prep --x509 --46
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east
echo "initdone"
