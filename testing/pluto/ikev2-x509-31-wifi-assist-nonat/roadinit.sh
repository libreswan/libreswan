/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/road.p12
/testing/x509/import.sh real/mainca/east.end.cert
../../guestbin/ip.sh address add 192.1.3.210/24 dev eth0
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add rw-lte
ipsec auto --add rw-wifi
echo "initdone"
