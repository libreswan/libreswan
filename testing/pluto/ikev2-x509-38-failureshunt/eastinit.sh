/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec auto --add failureshunt
ipsec status
echo "initdone"
