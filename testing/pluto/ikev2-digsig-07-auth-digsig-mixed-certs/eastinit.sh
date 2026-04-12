/testing/guestbin/swan-prep --x509
/testing/x509/import.sh real/mainec/root.cert
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
