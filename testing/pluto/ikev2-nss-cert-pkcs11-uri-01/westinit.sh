/testing/guestbin/swan-prep --nokeys --nsspw

/testing/x509/import.sh real/mainca/`hostname`.all.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
