/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/east.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec auto --add distraction
ipsec auto --status | grep westnet-eastnet
echo "initdone"
