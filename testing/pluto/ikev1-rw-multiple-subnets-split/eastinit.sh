/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/road.end.cert
../../guestbin/ip.sh address add 192.0.20.254/24 dev eth0
ipsec pluto --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
echo "initdone"
