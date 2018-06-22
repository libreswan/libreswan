/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-a
ipsec auto --add northnet-eastnet-b
echo "initdone"
