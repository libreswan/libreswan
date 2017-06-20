/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add norhtnet-eastnets
ipsec auto --status | grep norhtnet-eastnets
echo "initdone"
