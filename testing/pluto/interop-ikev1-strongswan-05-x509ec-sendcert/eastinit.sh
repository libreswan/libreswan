/testing/guestbin/swan-prep --x509
ipsec setup start:
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev1-eccert
echo "initdone"
