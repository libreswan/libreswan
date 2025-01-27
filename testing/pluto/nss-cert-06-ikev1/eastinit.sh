/testing/guestbin/swan-prep --nokeys

ipsec pk12util -W foobar -K '' -i /testing/x509/real/mainca/east.all.p12
ipsec certutil -M -n mainca -t CT,,
ipsec certutil -A -i /testing/x509/real/otherca/root.cert -n "otherca" -t 'CT,,'
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-correct
ipsec auto --add nss-cert-wrong
ipsec auto --status |grep nss-cert
echo "initdone"
