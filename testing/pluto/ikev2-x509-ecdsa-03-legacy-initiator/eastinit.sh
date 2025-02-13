/testing/guestbin/swan-prep --hostkeys

/testing/x509/import.sh real/mainec/`hostname`.all.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec whack --impair suppress_retransmits
echo "initdone"
