/testing/guestbin/swan-prep --hostkeys

/testing/x509/import.sh real/mainca/root.cert
/testing/x509/import.sh real/mainca/west.end.cert
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
