/testing/guestbin/swan-prep --46 --nokeys

/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/key4096.end.cert

../../guestbin/ip.sh link set dev eth1 mtu 1480
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add v6-tunnel
echo "initdone"
