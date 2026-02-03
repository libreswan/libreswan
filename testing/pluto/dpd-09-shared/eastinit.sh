/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add northnet-eastnet-a
ipsec add northnet-eastnet-b
echo "initdone"
