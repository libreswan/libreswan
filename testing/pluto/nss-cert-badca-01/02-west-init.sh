/testing/guestbin/swan-prep --nokeys

ipsec certutil -A -i /testing/x509/real/mainca/root.cert -n "mainca" -t "CT,,"

ipsec pk12util -W foobar -i /testing/x509/real/badca/badwest.all.p12
ipsec certutil -M -n badca -t CT,,

# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
echo "initdone"
