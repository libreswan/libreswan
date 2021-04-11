/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-a-dpd
ipsec auto --add northnet-eastnet-b
echo "initdone"
