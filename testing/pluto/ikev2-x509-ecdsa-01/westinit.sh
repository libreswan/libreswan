/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainec/`hostname`.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west
ipsec whack --impair suppress_retransmits
echo "initdone"
