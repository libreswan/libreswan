/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.end.p12
/testing/x509/import.sh real/mainca/west.end.cert

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-x509
ipsec connectionstatus westnet-eastnet-x509
echo "initdone"
