/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/west.end.cert

sh ./gdb.sh & sleep 1
../../guestbin/wait-until-pluto-started

ipsec add westnet-eastnet-ikev2
echo "initdone"
