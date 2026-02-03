/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add north-a-dpd
ipsec add northnet-eastnet-b
echo "initdone"
