/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/west.end.cert
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2
ipsec add distraction
ipsec connectionstatus westnet-eastnet-ikev2
echo "initdone"
