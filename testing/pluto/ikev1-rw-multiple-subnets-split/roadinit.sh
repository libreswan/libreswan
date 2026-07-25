/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/road.p12
/testing/x509/import.sh real/mainca/east.end.cert
ipsec pluto --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
echo "initdone"
