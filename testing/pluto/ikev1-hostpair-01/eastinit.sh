/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/road.end.cert
# confirm that the network is alive
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add roadnet-eastnet-ipv4-psk-ikev1
echo "initdone"
