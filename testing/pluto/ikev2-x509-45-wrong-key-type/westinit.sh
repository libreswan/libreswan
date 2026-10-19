/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainec/west.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec add westnet-eastnet-ikev2
echo "initdone"
