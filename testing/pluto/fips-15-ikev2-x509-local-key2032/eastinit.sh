/testing/guestbin/swan-prep --nokeys
/testing/guestbin/fips.sh on

/testing/x509/import.sh real/mainca/key2032.p12

ipsec start
../../guestbin/wait-until-pluto-started
echo "initdone"
