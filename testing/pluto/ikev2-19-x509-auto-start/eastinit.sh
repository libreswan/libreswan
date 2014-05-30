/testing/guestbin/swan-prep --46 --x509
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --status
echo "initdone"
