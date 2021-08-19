/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-any
ipsec auto --add north-any
echo "initdone"
