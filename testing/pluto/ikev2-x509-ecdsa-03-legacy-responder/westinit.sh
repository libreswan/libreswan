/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainec/`hostname`.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec whack --impair suppress_retransmits
echo "initdone"
