/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-ipv4
ipsec auto --status | grep northnet-eastnet-ipv4
echo "initdone"
