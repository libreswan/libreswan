/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/east.p12

ipsec start
../../guestbin/wait-until-pluto-started

# beware the groundhog!
ipsec add east
ipsec checkpubkeys

echo "initdone"
