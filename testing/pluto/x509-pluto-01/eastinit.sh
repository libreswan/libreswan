/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.end.cert
/testing/x509/import.sh real/mainca/`hostname`.end.p12
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509-nosend
ipsec auto --status | grep westnet-eastnet-x509-nosend
echo "initdone"
