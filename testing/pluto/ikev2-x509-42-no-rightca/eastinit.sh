/testing/guestbin/swan-prep --nokeys
# load east's keypair + root's cert
/testing/x509/import.sh real/mainca/east.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add east
echo "initdone"
