/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/road.end.cert
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east
ipsec whack --impair revival
ipsec whack --impair rekey_respond_supernet
echo "initdone"
