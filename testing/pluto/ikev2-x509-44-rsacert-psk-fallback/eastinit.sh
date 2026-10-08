/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/root.cert
/testing/x509/import.sh real/mainca/west.end.cert

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-ikev2
ipsec connectionstatus westnet-eastnet-ikev2
echo "initdone"
