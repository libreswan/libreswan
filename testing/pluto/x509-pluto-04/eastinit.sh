/testing/guestbin/swan-prep --nokeys

# east and a root cert
/testing/x509/import.sh real/mainca/east.p12
# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-x509-cr
ipsec auto --status | grep westnet-eastnet-x509-cr
echo "initdone"
