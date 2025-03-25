/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/`hostname`.p12

ipsec start
../../guestbin/wait-until-pluto-started
echo initdone
