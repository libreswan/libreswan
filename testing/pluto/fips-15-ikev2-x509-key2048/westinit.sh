/testing/guestbin/swan-prep --x509 --x509name mediumkey
fipscheck
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
