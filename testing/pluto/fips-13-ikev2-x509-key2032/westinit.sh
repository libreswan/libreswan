/testing/guestbin/swan-prep --nokeys

# so this end can sign its own cert
/testing/x509/import.sh real/mainca/key2032.p12

ipsec start
../../guestbin/wait-until-pluto-started

ipsec add westnet-eastnet-ikev2
ipsec whack --impair revival
echo "initdone"
