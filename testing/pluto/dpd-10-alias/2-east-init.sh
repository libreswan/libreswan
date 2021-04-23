/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add northnet-eastnets
ipsec auto --status | grep northnet-eastnets
echo "initdone"
