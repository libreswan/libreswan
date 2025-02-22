/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/east.end.cert
# WEST will send NORTHs cert
ipsec pk12util -W foobar -K '' -i /testing/x509/real/mainca/north.end.p12
# I guess this is a distraction?
ipsec pk12util -W foobar -K '' -i /testing/x509/real/otherca/otherwest.all.p12
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"
