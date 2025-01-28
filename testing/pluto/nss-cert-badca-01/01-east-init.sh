/testing/guestbin/swan-prep --nokeys

# pull in the full east
ipsec pk12util -W foobar -i /testing/x509/real/mainca/east.all.p12
ipsec certutil -M -n mainca -t CT,,

ipsec pk12util -W foobar -K '' -i /testing/x509/real/badca/badeast.all.p12
ipsec certutil -M -n badca -t CT,,
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert
ipsec auto --status |grep nss-cert
echo "initdone"
