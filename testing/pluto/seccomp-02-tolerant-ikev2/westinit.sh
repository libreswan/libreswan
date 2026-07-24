/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.p12
/testing/x509/import.sh real/mainca/east.end.cert
# why start pluto directly?
mkdir -p /var/run/pluto
ipsec pluto --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
ipsec add nss-cert
echo "initdone"
