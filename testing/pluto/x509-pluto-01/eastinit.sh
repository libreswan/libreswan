/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.end.cert
/testing/x509/import.sh real/mainca/`hostname`.end.p12
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-x509-nosend
ipsec connectionstatus westnet-eastnet-x509-nosend
echo "initdone"
