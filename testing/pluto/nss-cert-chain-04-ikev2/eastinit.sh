/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/east.all.p12
/testing/x509/import.sh real/otherca/root.cert
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add road-A
ipsec add road-chain-B
ipsec auto --status |grep road
echo "initdone"
