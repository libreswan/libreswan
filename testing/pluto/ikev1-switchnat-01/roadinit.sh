/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/road.p12
/testing/x509/import.sh real/mainca/east.end.cert
../../guestbin/ip.sh address add 192.1.3.208/24 dev eth0
ipsec start
../../guestbin/wait-until-pluto-started
echo "initdone"
