/testing/guestbin/swan-prep --nokeys --fips

/testing/x509/import.sh real/mainec/`hostname`.all.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east
ipsec whack --impair suppress_retransmits
echo "initdone"
