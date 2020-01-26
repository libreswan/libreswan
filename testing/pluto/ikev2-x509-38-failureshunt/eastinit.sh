/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add failureshunt
ipsec auto --add westnet-eastnet
ipsec status
echo "initdone"
