/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.p12
/testing/x509/import.sh real/mainca/east.end.cert
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
