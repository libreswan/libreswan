/testing/guestbin/swan-prep --nokeys

# import west's cert (no CA)
/testing/x509/import.sh real/mainca/west.end.cert
# import fake east cert+key (again no CA)
/testing/x509/import.sh fake/mainca/east.end.p12
# confirm
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"
